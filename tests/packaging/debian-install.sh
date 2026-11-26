#!/usr/bin/env bash
# Installation of the agent .deb (ADR-0024) in a Debian container whose
# PID 1 is systemd, connected to a test core running on the host. Runs on a
# CI runner with Docker and passwordless sudo.
#
#   tests/packaging/debian-install.sh debian:12 ostena-agent_0.0.0_amd64.deb test_core
#
# Checks: postinst (system user, idempotent), `ostena agent setup` with the
# root fingerprint, the service active and connected to the core, no
# listening port of the agent (dial-back only), the control socket refused
# to a non-root user, setup run again changes nothing, reinstallation
# (upgrade path), removal (service gone, configuration kept), purge.
set -euo pipefail

IMAGE=${1:?Debian image, e.g. debian:12}
DEB=${2:?path to the .deb}
TEST_CORE=${3:?path to the test_core example (host binary)}
GROUP=2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6
NAME=ostena-pkg-$$
UNIT=ostena-agent.service

work=$(mktemp -d)
core_pid=
cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    exec 7>&- 2>/dev/null || true
    [ -n "$core_pid" ] && kill "$core_pid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

dx() { docker exec "$NAME" "$@"; }
fail() {
    echo "::error::[$IMAGE] $*"
    dx journalctl -u "$UNIT" --no-pager -n 80 2>/dev/null || true
    exit 1
}

echo "=== [$IMAGE] test core on the host"
mkdir -p "$work/core"
cp "$DEB" "$work/ostena-agent.deb"
mkfifo "$work/core.in"
"$TEST_CORE" "$work/core" "$GROUP" <"$work/core.in" >"$work/core.out" 2>&1 &
core_pid=$!
exec 7>"$work/core.in" # the core serves until its standard input closes
for _ in $(seq 1 50); do grep -q '^core ' "$work/core.out" && break; sleep 0.2; done
core=$(sed -n 's/^core //p' "$work/core.out")
[ -n "$core" ] || { cat "$work/core.out"; fail "the test core did not start"; }
chmod -R a+rX "$work"
echo "core at $core"

echo "=== [$IMAGE] container with systemd as PID 1"
# Host network: the test core listens on the loopback of the host. Its own
# cgroup namespace; privileged for the sandboxing of the unit.
docker run -d --name "$NAME" --privileged --cgroupns=private --network host -e container=docker \
    --tmpfs /run --tmpfs /run/lock -v "$work:/work:ro" "$IMAGE" bash -c '
        set -e
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
            systemd systemd-sysv dbus iproute2 >/dev/null
        exec /sbin/init' >/dev/null
for _ in $(seq 1 180); do
    state=$(dx systemctl is-system-running 2>/dev/null || true)
    case "$state" in running | degraded) break ;; esac
    sleep 1
done
case "$state" in running | degraded) ;; *) docker logs "$NAME" | tail -20; fail "systemd did not start ($state)" ;; esac
dx cat /etc/debian_version
dx systemctl --version | head -1

echo "=== [$IMAGE] dpkg -i"
dx dpkg -i /work/ostena-agent.deb
dx getent passwd ostena | grep -q ':/nonexistent:/usr/sbin/nologin$' || fail "system user ostena"
# postinst is idempotent.
dx /var/lib/dpkg/info/ostena-agent.postinst configure >/dev/null
dx /var/lib/dpkg/info/ostena-agent.postinst configure >/dev/null
[ "$(dx getent passwd ostena | wc -l)" = 1 ] || fail "postinst created the user twice"
dx test ! -e /etc/systemd/system/$UNIT || fail "postinst installed the service before setup"

echo "=== [$IMAGE] ostena agent setup"
# The identity issued by the test core, where enrolment would write it.
dx install -d -m 0700 /var/lib/ostena
dx cp /work/core/agent.crt /work/core/agent.key /var/lib/ostena/
fingerprint=$(sed '/-----/d' "$work/core/root.pem" | base64 -d | sha256sum | cut -d' ' -f1)
# A wrong fingerprint is refused, and nothing is written.
wrong=$(printf '%064d' 0)
if dx ostena agent setup --core-address "$core" --gateway-group "$GROUP" \
    --root-ca /work/core/root.pem --root-fingerprint "$wrong"; then
    fail "setup accepted a root with another fingerprint"
fi
dx test ! -e /etc/ostena/ostena.toml || fail "setup wrote a configuration despite the wrong root"
dx ostena agent setup --core-address "$core" --gateway-group "$GROUP" \
    --root-ca /work/core/root.pem --root-fingerprint "$fingerprint" --log /etc/ostena/setup.log
for _ in $(seq 1 30); do [ "$(dx systemctl is-active $UNIT || true)" = active ] && break; sleep 1; done
[ "$(dx systemctl is-active $UNIT || true)" = active ] || fail "the service is not active"
dx stat -c '%U:%G %a %n' /etc/ostena/ostena.toml /etc/ostena/root.pem /var/lib/ostena/agent.key
[ "$(dx stat -c '%U:%G %a' /etc/ostena/ostena.toml)" = "root:ostena 640" ] || fail "configuration permissions"
[ "$(dx stat -c '%U %a' /var/lib/ostena/agent.key)" = "ostena 600" ] || fail "key permissions"
dx grep -q '^mode = "production"' /etc/ostena/ostena.toml || fail "configuration not in production mode"
if dx grep -q 'agent.ssh' /etc/ostena/ostena.toml; then fail "setup configured an SSH server"; fi

echo "=== [$IMAGE] status (root): connected to the core"
connected=
for _ in $(seq 1 30); do
    if dx ostena agent status >"$work/status.txt" && grep -q '^Core : connecté (' "$work/status.txt"; then
        connected=1
        break
    fi
    sleep 1
done
cat "$work/status.txt"
[ -n "$connected" ] || fail "the agent did not connect to the core"

echo "=== [$IMAGE] no listening port (dial-back only)"
pid=$(dx systemctl show -p MainPID --value $UNIT)
dx ss -Hltnp >"$work/tcp.txt"
dx ss -Hlunp >"$work/udp.txt"
grep "pid=$pid," "$work/tcp.txt" && fail "the agent listens on TCP"
udp=$(grep -c "pid=$pid," "$work/udp.txt" || true)
grep "pid=$pid," "$work/udp.txt" || true
# The QUIC client socket of the link to the core, nothing else.
[ "$udp" -le 1 ] || fail "the agent holds $udp UDP sockets"
if grep "pid=$pid," "$work/udp.txt" | awk '{print $4}' | grep -Eq ':([0-9]{1,3}|10[01][0-9]|102[0-3])$'; then
    fail "UDP socket of the agent on a well-known port"
fi
echo "agent pid $pid: no TCP listener, $udp UDP client socket"

echo "=== [$IMAGE] control socket refused to a non-root user"
set +e
out=$(dx runuser -u nobody -- /usr/bin/ostena agent status 2>&1)
code=$?
set -e
echo "$out"
[ "$code" != 0 ] || fail "a non-root user reached the control socket"
if grep -q '^Groupe :' <<<"$out"; then fail "a non-root user read the agent status"; fi
grep -q 'AGT-E00[789]' <<<"$out" || fail "no AGT-E007/E008/E009 for a non-root user"
if dx runuser -u nobody -- test -e /run/ostena/agent.sock; then fail "the control socket is visible to a non-root user"; fi

echo "=== [$IMAGE] setup again: nothing changes"
before=$(dx sha256sum /etc/ostena/ostena.toml)
dx ostena agent setup --core-address "$core" --gateway-group "$GROUP" --quiet
[ "$(dx sha256sum /etc/ostena/ostena.toml)" = "$before" ] || fail "setup rewrote the configuration"
if dx ostena agent setup --core-address elsewhere.invalid:8443 --quiet 2>"$work/err.txt"; then
    fail "setup accepted another core address"
fi
grep -q core_address "$work/err.txt" || fail "no explanation for the refused core address"

echo "=== [$IMAGE] reinstallation (upgrade path): the service restarts on the package binary"
dx dpkg -i /work/ostena-agent.deb
for _ in $(seq 1 30); do [ "$(dx systemctl is-active $UNIT || true)" = active ] && break; sleep 1; done
[ "$(dx systemctl is-active $UNIT || true)" = active ] || fail "the service is not active after reinstallation"
dx grep -q '^ExecStart=/usr/bin/ostena agent run' /etc/systemd/system/$UNIT || fail "unit ExecStart"

echo "=== [$IMAGE] removal: service gone, configuration and identity kept"
dx dpkg -r ostena-agent
dx test ! -e /etc/systemd/system/$UNIT || fail "unit left behind"
dx test ! -e /usr/bin/ostena || fail "binary left behind"
dx test -f /etc/ostena/ostena.toml || fail "configuration removed by dpkg -r"
dx test -f /var/lib/ostena/agent.key || fail "identity removed by dpkg -r"
[ "$(dx systemctl is-active $UNIT || true)" != active ] || fail "the service still runs"

echo "=== [$IMAGE] purge"
dx dpkg -P ostena-agent
dx test ! -e /etc/ostena/ostena.toml || fail "configuration left after purge"
dx test ! -e /var/lib/ostena || fail "state left after purge"
echo "OK ($IMAGE)"
