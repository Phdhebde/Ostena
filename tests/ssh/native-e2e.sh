#!/usr/bin/env bash
# Native SSH access end to end (ADR-0010): the system OpenSSH client, with a
# certificate as `ostena login` will issue, through the real agent binary
# (`ostena agent run` with [agent.ssh]: gateway, in-process test core, grant,
# scope) to a real OpenSSH 9.2 target (Debian 12) holding the agent key as
# `restrict,from=`. The scenario is the test `agent_ssh` of ostena-cli; this
# script gives it a target outside this host (the scope control refuses the
# loopback and the agent's own addresses).
#
# Two ways to run it:
# - with Docker (CI): the script starts the Debian 12 target, reached on its
#   container address;
# - against a given target, when Docker is not available here: set
#   OSTENA_E2E_TARGET (ip:port, not an address of this host),
#   OSTENA_E2E_TARGET_USER, OSTENA_E2E_AGENT_KEY (private key whose public
#   key is in the target authorized_keys; imported as the agent key on the
#   targets) and OSTENA_E2E_TARGET_HOST_KEY (file holding the target ECDSA
#   P-256 host key line).
#
# Needs ssh and ssh-keygen. Usage: tests/ssh/native-e2e.sh
set -euo pipefail

work="$(mktemp -d)"
name="ostena-ssh-e2e-$$"
cleanup() {
  if [ -z "${OSTENA_E2E_TARGET:-}" ] || [ -n "${started_target:-}" ]; then
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

target_dir="${CARGO_TARGET_DIR:-target}"
cargo build --quiet --locked -p ostena-ssh --example footprint_server
check="$target_dir/debug/examples/footprint_server"
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi; }

if [ -z "${OSTENA_E2E_TARGET:-}" ]; then
  started_target=1
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

OSTENA_REQUIRE_OPENSSH=1 cargo test --locked -p ostena-cli --test agent_ssh \
  native_ssh_through_the_real_agent -- --nocapture
echo "native e2e : ok"
