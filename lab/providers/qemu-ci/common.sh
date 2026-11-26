# Shared helpers of the qemu-ci provider (ADR-0025). Sourced, not run.
# shellcheck shell=bash

QEMU_CI_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LAB_DIR=$(cd "$QEMU_CI_DIR/../.." && pwd)
LABCONFIG=(python3 "$LAB_DIR/tools/labconfig.py")
: "${LAB_WORK:?LAB_WORK must name the work directory (see preflight.sh)}"
LAB_STATE=${LAB_STATE:-$LAB_WORK/state}
LAB_RUN=${LAB_RUN:-$LAB_WORK/run}

log() { printf '[lab %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() { printf '::error title=Lab::%s\n' "$*"; exit 1; }

# Virtual hardware, identical for the base build and the lab machines so
# that Windows keeps the same drivers: q35, AHCI disk with TRIM, Intel
# e1000 NIC (drivers included in Windows Server 2016 and 2022, no virtio
# driver to download), Hyper-V enlightenments for the guest clock and locks.
# Usage: qemu_hw <array-name> <name> <memory-mb> <cpus> <disk>
qemu_hw() {
  local -n _args=$1
  local name=$2 mem=$3 cpus=$4 disk=$5
  _args=(
    qemu-system-x86_64 -name "$name"
    -machine q35,accel=kvm -cpu host,hv_relaxed,hv_vapic,hv_spinlocks=0x1fff,hv_time
    -smp "$cpus" -m "$mem" -rtc base=utc
    -drive "file=$disk,if=none,id=disk0,format=qcow2,discard=unmap,detect-zeroes=unmap,cache=unsafe"
    -device ide-hd,drive=disk0,bus=ide.0,bootindex=1
    -display none -vga std
    -monitor "unix:$LAB_RUN/$name.monitor,server,nowait"
    -serial "file:$LAB_RUN/$name.serial"
  )
}

# Sends one command to the QEMU monitor of a machine.
monitor() {
  local name=$1; shift
  printf '%s\n' "$*" | socat -t 2 - "UNIX-CONNECT:$LAB_RUN/$name.monitor" >/dev/null 2>&1 || true
}

# Screenshot of a machine's console, for the failure diagnostics.
screenshot() {
  local name=$1 dir=$LAB_RUN/shots
  mkdir -p "$dir"
  monitor "$name" "screendump $dir/$name-$(date -u +%H%M%S).png -f png"
}

# Records a duration in <state>/timings.json.
timing() {
  python3 - "$LAB_STATE/timings.json" "$1" "$2" <<'EOF'
import json, sys
path, key, value = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    data = json.load(open(path))
except (OSError, ValueError):
    data = {}
data[key] = value
json.dump(data, open(path, "w"), indent=2, sort_keys=True)
EOF
}
