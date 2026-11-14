#!/usr/bin/env bash
# Resident memory of the SSH server of ostena-ssh (frozen list, pre-check):
# idle, then with 1 and 50 sessions opened by the OpenSSH client. Linux only
# (reads /proc). Needs ssh and ssh-keygen. Usage: tests/ssh/footprint.sh
set -euo pipefail

work="$(mktemp -d)"
server_pid=""
cleanup() {
  jobs -p | xargs -r kill 2>/dev/null || true
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

cargo build --quiet --release --locked -p ostena-ssh --example footprint_server
# ssh-key 0.7.0-rc.11 refuses about one P-256 key in 256 (ADR-0010): make the
# key again until the server can load it.
key() {
  for _ in $(seq 1 16); do
    rm -f "$1" "$1.pub"
    ssh-keygen -q -t ecdsa -b 256 -N "" -f "$1"
    target/release/examples/footprint_server --check "$1" && return 0
  done
  return 1
}
key "$work/host"
key "$work/client"

target/release/examples/footprint_server "$work/host" "$work/client.pub" > "$work/out" &
server_pid=$!
for _ in $(seq 1 50); do grep -q listening "$work/out" 2>/dev/null && break; sleep 0.1; done
port="$(sed -n 's/^listening 127.0.0.1://p' "$work/out")"
echo "[127.0.0.1]:$port $(cut -d' ' -f1-2 "$work/host.pub")" > "$work/known_hosts"

rss() { awk '/^VmRSS/ {printf "%.1f MiB", $2 / 1024}' "/proc/$server_pid/status"; }
anon() { awk '/^RssAnon/ {printf "%.1f MiB", $2 / 1024}' "/proc/$server_pid/status"; }
client() {
  ssh -F none -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$work/known_hosts" \
    -o IdentitiesOnly=yes -i "$work/client" -p "$port" tester@127.0.0.1 "$@"
}

sleep 1
echo "idle: $(rss) (anonymous $(anon))"
# Each open session holds one more socket in the server.
base=$(ls "/proc/$server_pid/fd" | wc -l)
[ "$(client ok)" = ok ] || { echo "session failed"; exit 1; }

opened=0
for n in 1 50; do
  while [ "$opened" -lt "$n" ]; do
    client hold >/dev/null 2>&1 &
    opened=$((opened + 1))
  done
  for _ in $(seq 1 100); do
    open=$(ls "/proc/$server_pid/fd" | wc -l)
    [ "$open" -ge $((base + n)) ] && break
    sleep 0.1
  done
  [ "$open" -ge $((base + n)) ] || { echo "only $((open - base)) of $n sessions opened"; exit 1; }
  sleep 2
  echo "$n session(s): $(rss) (anonymous $(anon))"
done
