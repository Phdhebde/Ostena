#!/usr/bin/env bash
# Integration test of the agent service under systemd (ADR-0007). Runs on a
# CI runner with systemd as PID 1 and passwordless sudo.
#
#   tests/agent/linux-service.sh target/release/ostena
set -euo pipefail

BIN=${1:?path to the ostena binary}
UNIT=ostena-agent.service
CONFIG=/etc/ostena/ostena.toml

fail() {
    echo "::error::$*"
    sudo journalctl -u "$UNIT" --no-pager -n 100 || true
    exit 1
}

wait_for() { # state, seconds
    for _ in $(seq 1 "$2"); do
        [ "$(systemctl is-active "$UNIT" || true)" = "$1" ] && return 0
        sleep 1
    done
    return 1
}

echo "=== install (production configuration)"
sudo install -m 0755 "$BIN" /usr/local/bin/ostena
sudo install -d -m 0755 /etc/ostena
sudo tee "$CONFIG" >/dev/null <<'TOML'
mode = "production"

[agent]
gateway_group = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
core_address = "core.invalid:8443"
tls_certificate = "/var/lib/ostena/agent.crt"
tls_private_key = "/var/lib/ostena/agent.key"
tls_core_ca = "/etc/ostena/core-ca.pem"
replay_journal = "/var/lib/ostena/replay.journal"
shutdown_grace_secs = 5

[agent.ssh]
listen = ["127.0.0.1:2222"]
TOML
# The identity lives in the state directory, where the service may write
# (renewal).
sudo install -d -m 0700 /var/lib/ostena
echo "not a real key" | sudo tee /var/lib/ostena/agent.key >/dev/null
sudo ostena agent install --config "$CONFIG"
wait_for active 30 || fail "the service did not become active"

echo "=== permissions"
sudo stat -c '%U:%G %a %n' "$CONFIG" /var/lib/ostena/agent.key /var/lib/ostena /run/ostena /run/ostena/agent.sock
[ "$(sudo stat -c '%U %a' /var/lib/ostena/agent.key)" = "ostena 600" ] || fail "private key permissions"
[ "$(sudo stat -c '%U %a' /run/ostena)" = "ostena 700" ] || fail "runtime directory permissions"
[ "$(sudo stat -c '%U %a' /run/ostena/agent.sock)" = "ostena 600" ] || fail "socket permissions"

echo "=== native SSH server (ADR-0010): keys created by the service, listening, no handshake without identity"
for key in ssh_host_key ssh_target_key; do
    [ "$(sudo stat -c '%U %a' /var/lib/ostena/$key)" = "ostena 600" ] || fail "$key permissions"
done
ss -ltn | grep -q '127.0.0.1:2222 ' || fail "the SSH server does not listen on 127.0.0.1:2222"
# Without a core, no host certificate is pushed: the server accepts the
# connection and closes it before its identification, with an audit event.
rc=0
reply=$(timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/2222 || exit 9; head -c 14 <&3') || rc=$?
[ "$rc" = 0 ] || fail "SSH server: connection refused or left open (exit $rc)"
[ -z "$reply" ] || fail "SSH identification sent without a host identity: '$reply'"
refused() {
    sudo journalctl -u "$UNIT" --no-pager | grep '"ssh.connection_refused"' | grep -q '"code":"SSH-E018"'
}
for _ in $(seq 1 20); do refused && break; sleep 0.5; done
refused || fail "no ssh.connection_refused (SSH-E018) for a connection without identity"
line=$(sudo ostena agent ssh-key --config "$CONFIG" --line --from 10.20.0.11)
echo "$line"
case "$line" in
    'restrict,from="10.20.0.11" ecdsa-sha2-nistp256 '*) ;;
    *) fail "authorized_keys line: $line" ;;
esac

echo "=== status (root)"
sudo ostena agent status --config "$CONFIG" | tee status.txt
grep -q "Groupe : 2f6c9a4e" status.txt || fail "status did not reach the control plane"
grep -q "SSH : à l'écoute sur 127.0.0.1:2222" status.txt || fail "status does not show the SSH server"
grep -q "Identité SSH : pas encore reçue du core" status.txt || fail "status does not show the pending SSH identity"

echo "=== status (unprivileged user): refused"
if ostena agent status --config "$CONFIG" --pid 1; then fail "an unprivileged user reached the control plane"; fi

echo "=== hardening"
sudo systemd-analyze security "$UNIT" --no-pager | tail -1
sudo cp /etc/systemd/system/$UNIT "${RUNNER_TEMP:-/tmp}/$UNIT"

echo "=== clean stop"
sudo systemctl stop "$UNIT"
sudo journalctl -u "$UNIT" --no-pager | grep -q '"agent.stopped"' || fail "no agent.stopped event"
sudo journalctl -u "$UNIT" --no-pager | grep -q '"agent.sessions_closed"' || fail "no agent.sessions_closed event"
sudo journalctl -u "$UNIT" --no-pager | grep -q '"agent.ssh_stopped"' || fail "no agent.ssh_stopped event"

echo "=== bounded restarts: at most 3 in 10 minutes"
sudo systemctl reset-failed "$UNIT" || true
sudo systemctl start "$UNIT"
wait_for active 30 || fail "restart"
for attempt in 1 2 3 4 5; do
    pid=$(systemctl show -p MainPID --value "$UNIT")
    [ "$pid" != "0" ] && sudo kill -KILL "$pid"
    sleep 7
    state=$(systemctl is-active "$UNIT" || true)
    echo "after kill $attempt: $state"
    [ "$state" = "failed" ] && break
done
[ "$state" = "failed" ] || fail "the service kept restarting"
sudo systemctl reset-failed "$UNIT"

echo "=== uninstall"
sudo ostena agent uninstall
[ ! -e /etc/systemd/system/$UNIT ] || fail "unit file left behind"
set +e
ostena agent status --config "$CONFIG"
code=$?
set -e
[ "$code" = "4" ] || fail "status after uninstall: exit $code, expected 4"

if [ -n "${SKIP_DEBIAN12:-}" ]; then echo "OK (Debian 12 check skipped)"; exit 0; fi
echo "=== unit on systemd 252 (Debian 12, oldest supported)"
# Any message from verify (unknown directive, wrong value) fails the test.
docker run --rm -v "${RUNNER_TEMP:-/tmp}/$UNIT:/tmp/$UNIT:ro" debian:12 bash -c '
    set -e
    install -m 0644 /tmp/ostena-agent.service /etc/systemd/system/ostena-agent.service
    apt-get update -qq >/dev/null
    apt-get install -y -qq --no-install-recommends systemd >/dev/null 2>&1
    install -m 0755 /dev/null /usr/local/bin/ostena
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin ostena
    systemctl --version | head -1
    out=$(systemd-analyze verify /etc/systemd/system/ostena-agent.service 2>&1)
    if [ -n "$out" ]; then echo "$out"; exit 1; fi
    systemd-analyze security --offline=yes /etc/systemd/system/ostena-agent.service | tail -1'
echo "OK"
