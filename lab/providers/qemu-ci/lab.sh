#!/usr/bin/env bash
# qemu-ci provider of the lab (ADR-0025): runs the machines of
# lab/machines.json as QEMU/KVM guests on one Linux host (a GitHub-hosted
# runner), on Linux bridges, with nftables enforcing the isolated zone.
#
# Usage: lab/providers/qemu-ci/lab.sh <command>
#   net-up            bridges, taps, nftables rules, lab control service
#   up                draw the run's secrets, create the overlays and the
#                     configuration media, start every machine
#   wait              follow the provisioning until every machine is ready,
#                     then write $LAB_WORK/out/lab.json
#   exec <vm> <file>  run a PowerShell script on a machine (pull channel),
#                     print its output and exit with its code
#   smoke             checks of the lab (certificates, isolation, channel)
#   collect <dir>     copy diagnostics without any secret (screenshots,
#                     serial logs, progress reports, timings)
#   down              stop the machines, remove the network
#
# Needs: preflight.sh run first (LAB_WORK), base images in $LAB_WORK/base.
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

OUT=$LAB_WORK/out
SELF=$QEMU_CI_DIR/lab.sh
VMS_DIR=$LAB_WORK/vms
mkdir -p "$LAB_STATE" "$LAB_RUN" "$OUT" "$VMS_DIR"

control_port() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["host"]["control_port"])' "$LAB_DIR/machines.json"; }
segments() {
  python3 - "$LAB_DIR/machines.json" <<'EOF'
import ipaddress, json, sys
lab = json.load(open(sys.argv[1]))
for name, seg in lab["segments"].items():
    print(name, seg["gateway"], ipaddress.ip_network(seg["cidr"]).prefixlen)
EOF
}
vms() { "${LABCONFIG[@]}" vms; }
vm_names() { vms | cut -f1; }

cmd_net_up() {
  sudo sysctl -qw net.ipv4.ip_forward=1
  # Bridged frames must not cross the host's iptables (Docker's FORWARD
  # policy drops them); the lab's own rules are in the nftables table below.
  if [[ -e /proc/sys/net/bridge/bridge-nf-call-iptables ]]; then
    sudo sysctl -qw net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-ip6tables=0
  fi
  if command -v iptables >/dev/null; then
    sudo iptables -I FORWARD 1 -i ost-+ -j ACCEPT
    sudo iptables -I FORWARD 1 -o ost-+ -j ACCEPT
  fi
  while read -r name gw prefix; do
    sudo ip link add "ost-$name" type bridge
    sudo ip addr add "$gw/$prefix" dev "ost-$name"
    sudo ip link set "ost-$name" up
  done < <(segments)
  while IFS=$'\t' read -r name _role _image _seg _ip _mem _cpus _mac bridge tap; do
    sudo ip tuntap add dev "$tap" mode tap user "$(id -un)"
    sudo ip link set "$tap" master "$bridge" up
    log "network: $name on $bridge ($tap)"
  done < <(vms)
  "${LABCONFIG[@]}" nft >"$LAB_RUN/lab.nft"
  sudo nft -f "$LAB_RUN/lab.nft"
  log "network: nftables table inet ostena_lab loaded"

  # shellcheck disable=SC2046
  nohup python3 "$LAB_DIR/tools/labhost.py" "$LAB_STATE" "$(control_port)" $(vm_names) \
    >"$LAB_RUN/labhost.log" 2>&1 &
  echo $! >"$LAB_RUN/labhost.pid"
  for _ in $(seq 20); do
    curl -fsS "http://127.0.0.1:$(control_port)/ping" >/dev/null 2>&1 && break
    sleep 0.5
  done
  curl -fsS "http://127.0.0.1:$(control_port)/ping" >/dev/null || fail "lab control service not started"
  log "control service listening on port $(control_port)"
}

cmd_up() {
  "${LABCONFIG[@]}" secrets "$LAB_STATE"
  date +%s >"$LAB_STATE/up_started"
  while IFS=$'\t' read -r name _role image _seg _ip mem cpus mac _bridge tap; do
    local base=$LAB_WORK/base/$image.qcow2
    [[ -f "$base" ]] || fail "base image $base missing"
    local disk=$VMS_DIR/$name.qcow2
    rm -f "$disk"
    qemu-img create -q -f qcow2 -b "$base" -F qcow2 "$disk"
    local cfg=$LAB_RUN/cfg-$name
    rm -rf "$cfg"
    mkdir -p "$cfg"
    "${LABCONFIG[@]}" vm-config "$LAB_STATE" "$name" "$cfg"
    cp "$LAB_DIR"/guest/provision/* "$cfg/"
    xorriso -as mkisofs -quiet -V OSTENA_CFG -J -R -o "$VMS_DIR/$name-cfg.iso" "$cfg"
    rm -rf "$cfg"
    chmod 0600 "$VMS_DIR/$name-cfg.iso"
    local args
    qemu_hw args "$name" "$mem" "$cpus" "$disk"
    args+=(
      -drive "file=$VMS_DIR/$name-cfg.iso,media=cdrom,if=none,id=cd0,readonly=on" -device ide-cd,drive=cd0,bus=ide.1
      -netdev "tap,id=net0,ifname=$tap,script=no,downscript=no" -device "e1000,netdev=net0,mac=$mac"
      -daemonize -pidfile "$LAB_RUN/$name.pid"
    )
    rm -f "$LAB_RUN/$name.serial"
    "${args[@]}"
    log "started $name ($image, $mem MiB, $cpus vCPU)"
  done < <(vms)
}

state_of() {
  local f=$LAB_STATE/status/$1.json
  [[ -f "$f" ]] && python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("state",""), "|", d.get("step",""), "|", d.get("message",""))' "$f" || echo "pending | - | no report yet"
}

cmd_wait() {
  local timeout_min=${LAB_UP_TIMEOUT_MIN:-150}
  local started
  started=$(cat "$LAB_STATE/up_started")
  local deadline=$(( started + timeout_min * 60 ))
  local seen=0 last_shot
  last_shot=$(date +%s)
  declare -A ready_at=()
  while true; do
    local lines
    lines=$(wc -l <"$LAB_RUN/labhost.log")
    if (( lines > seen )); then
      sed -n "$((seen + 1)),${lines}p" "$LAB_RUN/labhost.log" | grep ' report ' || true
      seen=$lines
    fi
    local all=1 name
    for name in $(vm_names); do
      local st
      st=$(state_of "$name")
      case "$st" in
        ready*)
          if [[ -z "${ready_at[$name]:-}" ]]; then
            ready_at[$name]=$(( $(date +%s) - started ))
            timing "ready_$name" "${ready_at[$name]}"
            log "$name ready after $(( ready_at[$name] / 60 )) min $(( ready_at[$name] % 60 )) s"
          fi ;;
        error*)
          for n in $(vm_names); do screenshot "$n"; done
          fail "$name: $st" ;;
        *) all=0 ;;
      esac
      if ! kill -0 "$(cat "$LAB_RUN/$name.pid" 2>/dev/null || echo 0)" 2>/dev/null; then
        fail "$name: QEMU is no longer running"
      fi
    done
    (( all )) && break
    local now
    now=$(date +%s)
    if (( now - last_shot >= 600 )); then
      for name in $(vm_names); do screenshot "$name"; log "$name: $(state_of "$name")"; done
      last_shot=$now
    fi
    if (( now > deadline )); then
      for name in $(vm_names); do screenshot "$name"; log "$name: $(state_of "$name")"; done
      fail "lab not ready after $timeout_min min"
    fi
    sleep 10
  done
  local total=$(( $(date +%s) - started ))
  timing lab_up "$total"
  log "lab ready in $(( total / 60 )) min $(( total % 60 )) s"
  "${LABCONFIG[@]}" assemble "$LAB_STATE" "$OUT" >/dev/null
  log "entry point: $OUT/lab.json"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "LAB_JSON=$OUT/lab.json" >>"$GITHUB_ENV"
  fi
}

cmd_exec() {
  local vm=${1:?machine} script=${2:?PowerShell script file, or - for stdin}
  local timeout_s=${LAB_EXEC_TIMEOUT_S:-600}
  local id
  id=t$(date +%s%N)
  local dir=$LAB_STATE/tasks/$vm
  mkdir -p "$dir/pending"
  if [[ "$script" == - ]]; then cat >"$dir/pending/$id.ps1.part"; else cp "$script" "$dir/pending/$id.ps1.part"; fi
  mv "$dir/pending/$id.ps1.part" "$dir/pending/$id.ps1"
  local deadline=$(( $(date +%s) + timeout_s ))
  while [[ ! -f "$dir/done/$id.json" ]]; do
    (( $(date +%s) < deadline )) || { echo "lab exec: no result from $vm after $timeout_s s" >&2; return 124; }
    sleep 1
  done
  python3 - "$dir/done/$id.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
sys.stdout.write(d.get("output") or "")
code = d.get("exit_code")
sys.exit(code if isinstance(code, int) and 0 <= code < 256 else 1)
EOF
}

json_get() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): d = d[k]
print(d)' "$OUT/lab.json" "$1"; }

cmd_smoke() {
  local failures=0
  check() { if "$@"; then log "ok: $CHECK"; else log "FAILED: $CHECK"; failures=$((failures + 1)); fi; }
  local name
  for name in $(vm_names); do
    local role ip
    role=$(json_get "machines.$name.role")
    ip=$(json_get "machines.$name.ip")
    CHECK="$name answers on the command channel"
    check bash -c "printf '%s\n' 'hostname' | '$SELF' exec '$name' - | grep -qi '^$name'"
    if [[ $role == member ]]; then
      local want got
      want=$(json_get "machines.$name.rdp.certificate.sha256")
      got=$(python3 "$QEMU_CI_DIR/tls_cert.py" rdp "$ip" 3389 || true)
      CHECK="$name serves the reported Remote Desktop certificate ($want)"
      check test "$got" = "$want"
      CHECK="$name is joined to the domain (secure channel)"
      check bash -c "printf '%s\n' 'if (Test-ComputerSecureChannel) { exit 0 } else { exit 1 }' | '$SELF' exec '$name' - >/dev/null"
    fi
    if [[ $role == dc ]]; then
      local want got
      want=$(json_get "machines.$name.ldaps.certificate.sha256")
      got=$(python3 "$QEMU_CI_DIR/tls_cert.py" tls "$ip" 636 || true)
      CHECK="$name serves the reported LDAPS certificate ($want)"
      check test "$got" = "$want"
    fi
  done

  # Isolated zone: what the gateway may and may not reach, seen from it.
  local gw dc host_dmz allowed="" refused="" member_ip
  gw=$(vms | awk -F'\t' '$2 == "gateway" {print $1; exit}')
  dc=$(json_get domain.dc_ip)
  host_dmz=$(json_get host.addresses.dmz)
  for member_ip in $(vms | awk -F'\t' '$2 == "member" {print $5}'); do
    allowed+="@('$member_ip', 3389, \$true), "
    refused+="@('$member_ip', 445, \$false), "
  done
  cat >"$LAB_RUN/probe.ps1" <<EOF
\$ErrorActionPreference = 'Continue'
function Probe([string]\$Address, [int]\$Port) {
  \$c = New-Object System.Net.Sockets.TcpClient
  try { return \$c.ConnectAsync(\$Address, \$Port).Wait(4000) -and \$c.Connected } catch { return \$false } finally { \$c.Dispose() }
}
\$expect = @(
  $allowed@('$dc', 88, \$true), @('$host_dmz', $(control_port), \$true),
  $refused@('$dc', 389, \$false), @('$dc', 445, \$false), @('$host_dmz', 22, \$false), @('1.1.1.1', 443, \$false)
)
\$bad = 0
foreach (\$e in \$expect) {
  \$open = Probe \$e[0] \$e[1]
  \$ok = (\$open -eq \$e[2])
  if (-not \$ok) { \$bad++ }
  Write-Output ("{0}:{1} open={2} expected={3} {4}" -f \$e[0], \$e[1], \$open, \$e[2], \$(if (\$ok) { 'ok' } else { 'WRONG' }))
}
exit \$bad
EOF
  CHECK="$gw reaches only the targets and the core"
  check "$SELF" exec "$gw" "$LAB_RUN/probe.ps1"

  # Nothing enters the isolated zone, not even from the host.
  local gw_ip before after
  gw_ip=$(json_get "machines.$gw.ip")
  before=$(sudo nft -j list counter inet ostena_lab dmz_inbound_refused | python3 -c 'import json,sys; print([o["counter"]["packets"] for o in json.load(sys.stdin)["nftables"] if "counter" in o][0])')
  CHECK="the host cannot open a connection to $gw"
  check bash -c "! timeout 6 bash -c '</dev/tcp/$gw_ip/445' 2>/dev/null"
  after=$(sudo nft -j list counter inet ostena_lab dmz_inbound_refused | python3 -c 'import json,sys; print([o["counter"]["packets"] for o in json.load(sys.stdin)["nftables"] if "counter" in o][0])')
  CHECK="the attempt was dropped by the isolation rules ($before -> $after packets)"
  check test "$after" -gt "$before"

  (( failures == 0 )) || fail "$failures smoke check(s) failed"
  log "smoke: all checks passed"
}

cmd_collect() {
  local dest=${1:?destination directory}
  mkdir -p "$dest"
  cp -r "$LAB_RUN/shots" "$dest/" 2>/dev/null || true
  cp "$LAB_RUN"/*.serial "$LAB_RUN/labhost.log" "$LAB_RUN/lab.nft" "$dest/" 2>/dev/null || true
  cp -r "$LAB_STATE/status" "$dest/" 2>/dev/null || true
  cp "$LAB_STATE/timings.json" "$dest/" 2>/dev/null || true
  cp -r "$LAB_WORK"/build/*/wiminfo.txt "$dest/" 2>/dev/null || true
  # Never: secrets.json, facts (keytab), lab.json, configuration media.
  if [[ -f "$LAB_STATE/secrets.json" ]]; then
    local value
    for value in $(python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
vals = [d["admin"], d["dsrm"], d["service"], d["local"], *d["domain"].values()]
print("\n".join(vals))' "$LAB_STATE/secrets.json"); do
      if grep -rqF "$value" "$dest"; then
        fail "a secret of the run appears in the diagnostics: not collected"
      fi
    done
  fi
  # Artifacts are not always at hand: the end of each guest log goes to the
  # job log too (checked above, no secret).
  local f
  for f in "$dest"/*.serial; do
    [[ -f "$f" ]] || continue
    echo "::group::$(basename "$f") (last 80 lines)"
    tail -n 80 "$f" | tr -d '\r'
    echo "::endgroup::"
  done
  log "diagnostics in $dest"
}

cmd_down() {
  local name
  for name in $(vm_names); do
    if [[ -f "$LAB_RUN/$name.pid" ]]; then kill "$(cat "$LAB_RUN/$name.pid")" 2>/dev/null || true; fi
  done
  if [[ -f "$LAB_RUN/labhost.pid" ]]; then kill "$(cat "$LAB_RUN/labhost.pid")" 2>/dev/null || true; fi
  sudo nft delete table inet ostena_lab 2>/dev/null || true
  while IFS=$'\t' read -r _name _role _image _seg _ip _mem _cpus _mac _bridge tap; do
    sudo ip link del "$tap" 2>/dev/null || true
  done < <(vms)
  while read -r seg _gw _prefix; do
    sudo ip link del "ost-$seg" 2>/dev/null || true
  done < <(segments)
  log "lab stopped"
}

command=${1:-}
shift || true
case "$command" in
  net-up) cmd_net_up ;;
  up) cmd_up ;;
  wait) cmd_wait ;;
  exec) cmd_exec "$@" ;;
  smoke) cmd_smoke ;;
  collect) cmd_collect "$@" ;;
  down) cmd_down ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
