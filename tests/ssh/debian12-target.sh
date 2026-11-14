#!/usr/bin/env bash
# Interoperability of the SSH client of ostena-ssh with a real OpenSSH server
# (Debian 12): starts sshd in a container, installs the client key with
# `restrict,from=` as ADR-0010 prescribes, then runs the `target` tests.
# Needs Docker and ssh-keygen. Usage: tests/ssh/debian12-target.sh
set -euo pipefail

port="${OSTENA_SSH_TARGET_PORT:-2222}"
name="ostena-ssh-target-$$"
work="$(mktemp -d)"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

# ssh-key 0.7.0-rc.11 refuses about one P-256 key in 256 (ADR-0010): make the
# key again until it can be loaded.
cargo build --quiet --locked -p ostena-ssh --example footprint_server
for _ in $(seq 1 16); do
  rm -f "$work/agent" "$work/agent.pub"
  ssh-keygen -q -t ecdsa -b 256 -N "" -C ostena-agent -f "$work/agent"
  check="$work/agent"
  if command -v cygpath >/dev/null 2>&1; then check="$(cygpath -w "$check")"; fi
  target/debug/examples/footprint_server --check "$check" && break
done
public="$(cat "$work/agent.pub")"

docker run -d --name "$name" -p "127.0.0.1:${port}:22" -e AGENT_KEY="$public" debian:12 sh -c '
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
echo "target: $(docker exec "$name" sh -c 'sshd -V 2>&1 | head -1' || true)"

export OSTENA_SSH_TARGET="127.0.0.1:${port}"
export OSTENA_SSH_TARGET_USER=ostena
key="$work/agent"
# Git Bash on Windows: give the test a Windows path.
if command -v cygpath >/dev/null 2>&1; then key="$(cygpath -w "$key")"; fi
export OSTENA_SSH_TARGET_KEY="$key"
export OSTENA_SSH_TARGET_HOST_KEY="$(docker exec "$name" cat /etc/ssh/ssh_host_ecdsa_key.pub | cut -d' ' -f1-2)"
export OSTENA_REQUIRE_TARGET=1
cargo test --locked -p ostena-ssh --test target
