#!/usr/bin/env bash
# Native SSH access end to end (ADR-0010): the system OpenSSH client, with a
# certificate as `ostena login` will issue, through the agent SSH server
# (example gateway_e2e: gateway, in-process test core, grant, scope) to a
# real OpenSSH 9.2 target (Debian 12) holding the agent key as
# `restrict,from=`.
#
# Two ways to run it:
# - with Docker (CI): the script starts the Debian 12 target, reached on its
#   container address (the loopback is refused by the scope control);
# - against a given target, when Docker is not available here: set
#   OSTENA_E2E_TARGET (ip:port, not a loopback address),
#   OSTENA_E2E_TARGET_USER, OSTENA_E2E_AGENT_KEY (private key whose public
#   key is in the target authorized_keys) and OSTENA_E2E_TARGET_HOST_KEY
#   (file holding the target ECDSA P-256 host key line).
#
# Needs ssh and ssh-keygen. Usage: tests/ssh/native-e2e.sh
set -euo pipefail

work="$(mktemp -d)"
name="ostena-ssh-e2e-$$"
agent_pid=""
cleanup() {
  if [ -n "$agent_pid" ]; then kill "$agent_pid" 2>/dev/null || true; fi
  if [ -z "${OSTENA_E2E_TARGET:-}" ]; then docker rm -f "$name" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT
fail() { echo "native e2e: ÉCHEC : $*" >&2; [ -f "$work/agent.log" ] && tail -n 40 "$work/agent.log" >&2; exit 1; }

target_dir="${CARGO_TARGET_DIR:-target}"
cargo build --quiet --locked -p ostena-ssh --example gateway_e2e --example footprint_server
bin="$target_dir/debug/examples/gateway_e2e"
check="$target_dir/debug/examples/footprint_server"
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi; }

if [ -z "${OSTENA_E2E_TARGET:-}" ]; then
  # ssh-key 0.7.0-rc.11 refuses about one P-256 key in 512 (ADR-0010).
  for _ in $(seq 1 16); do
    rm -f "$work/agent" "$work/agent.pub"
    ssh-keygen -q -t ecdsa -b 256 -N "" -C ostena-agent -f "$work/agent"
    "$check" --check "$(native "$work/agent")" && break
  done
  docker run -d --name "$name" -e AGENT_KEY="$(cat "$work/agent.pub")" debian:12 sh -c '
    set -e
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server iproute2 >/dev/null
    mkdir -p /run/sshd
    useradd -m ostena
    install -d -m 700 -o ostena -g ostena /home/ostena/.ssh
    gateway="$(ip route | awk "/default/ {print \$3}")"
    printf "restrict,from=\"%s\" %s\n" "$gateway" "$AGENT_KEY" > /home/ostena/.ssh/authorized_keys
    chown ostena:ostena /home/ostena/.ssh/authorized_keys
    chmod 600 /home/ostena/.ssh/authorized_keys
    touch /ready
    exec /usr/sbin/sshd -D -e
  ' >/dev/null
  for _ in $(seq 1 120); do
    docker exec "$name" test -f /ready 2>/dev/null && break
    sleep 1
  done
  docker exec "$name" test -f /ready
  sleep 1
  ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name")"
  export OSTENA_E2E_TARGET="$ip:22"
  export OSTENA_E2E_TARGET_USER=ostena
  export OSTENA_E2E_AGENT_KEY="$work/agent"
  docker exec "$name" cat /etc/ssh/ssh_host_ecdsa_key.pub > "$work/target_host.pub"
  export OSTENA_E2E_TARGET_HOST_KEY="$work/target_host.pub"
fi
echo "cible : $OSTENA_E2E_TARGET ($OSTENA_E2E_TARGET_USER)"

ssh-keygen -q -t ecdsa -b 256 -N "" -C user -f "$work/user"
"$bin" --target "$OSTENA_E2E_TARGET" \
  --target-host-key "$(native "$OSTENA_E2E_TARGET_HOST_KEY")" \
  --agent-key "$(native "$OSTENA_E2E_AGENT_KEY")" \
  --user-public "$(native "$work/user.pub")" \
  --account "$OSTENA_E2E_TARGET_USER" \
  --work "$(native "$work")" > "$work/agent.log" 2>&1 &
agent_pid=$!
for _ in $(seq 1 100); do
  [ -s "$work/port" ] && break
  kill -0 "$agent_pid" 2>/dev/null || fail "l'agent s'est arrêté"
  sleep 0.2
done
[ -s "$work/port" ] || fail "l'agent n'est pas prêt"
port="$(cat "$work/port")"

null=/dev/null
opts=(-F none -o BatchMode=yes -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=$work/known_hosts" -o "GlobalKnownHostsFile=$null"
  -o IdentitiesOnly=yes -o IdentityAgent=none -o ConnectTimeout=10
  -o "CertificateFile=$work/user-cert.pub" -i "$work/user" -p "$port")
user="$OSTENA_E2E_TARGET_USER"

# A command on the target, through the agent.
out="$(ssh "${opts[@]}" "$user@debian12@127.0.0.1" 'echo ok; id -un')" || fail "session refusée"
[ "$out" = "$(printf 'ok\n%s' "$user")" ] || fail "sortie inattendue : $out"
echo "session : ok"

# Refusals: unknown resource (refused by the core), sftp.
if ssh "${opts[@]}" "$user@unknown@127.0.0.1" true 2>/dev/null; then fail "ressource inconnue acceptée"; fi
if ssh "${opts[@]}" -s "$user@debian12@127.0.0.1" sftp </dev/null 2>/dev/null; then fail "sftp accepté"; fi
echo "refus : ok"

# Audit: the session went through the grant path and was closed.
for _ in $(seq 1 50); do
  grep -q '"event":"ssh.session_closed"' "$work/agent.log" && break
  sleep 0.2
done
for event in agent.ssh_trust_applied agent.session_granted ssh.session_opened ssh.exec \
  ssh.session_closed ssh.access_refused ssh.channel_refused; do
  grep -q "\"event\":\"$event\"" "$work/agent.log" || fail "événement $event absent"
done
grep -q '^closed reason=fermée bytes_to_target=0 bytes_from_target=' "$work/agent.log" ||
  fail "bilan de session absent"
echo "native e2e : ok"
