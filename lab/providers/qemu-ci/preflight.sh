#!/usr/bin/env bash
# Prepares a GitHub-hosted ubuntu-24.04 runner for the lab (ADR-0025):
# checks KVM, frees disk space, installs the lab tools and prints the
# measures (CPU, memory, disk) so that a failing run says why.
#
# Usage: lab/providers/qemu-ci/preflight.sh
# Variables:
#   LAB_MIN_FREE_GB  free space required on the work volume (default 60);
#                    below it, the preinstalled SDKs are removed first
#   LAB_SKIP_CLEANUP 1 to keep the preinstalled SDKs (local runs)
set -euo pipefail

min_free_gb=${LAB_MIN_FREE_GB:-60}

log() { printf '[preflight] %s\n' "$*"; }
fail() { printf '::error title=Lab preflight::%s\n' "$*"; exit 1; }

log "CPU: $(nproc) vCPU, $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2-)"
log "Memory: $(free -g | awk '/^Mem:/ {print $2}') GiB total, $(free -g | awk '/^Mem:/ {print $7}') GiB available"

# KVM: the GitHub Linux runners expose /dev/kvm; without it QEMU would fall
# back to emulation, far too slow for Windows. Fail explicitly instead.
if [[ ! -e /dev/kvm ]]; then
  fail "/dev/kvm is missing: hardware virtualization is not available on this runner"
fi
if ! grep -Eq '(vmx|svm)' /proc/cpuinfo; then
  fail "the CPU does not advertise vmx/svm: nested virtualization is off"
fi
# Same udev rule as the GitHub documentation: let the runner user open KVM.
echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
  | sudo tee /etc/udev/rules.d/99-kvm4all.rules >/dev/null
sudo udevadm control --reload-rules
sudo udevadm trigger --name-match=kvm
sudo chmod 0666 /dev/kvm
[[ -r /dev/kvm && -w /dev/kvm ]] || fail "/dev/kvm is not readable and writable by $(id -un)"
log "KVM: /dev/kvm present and usable"

free_on() { df -BG --output=avail "$1" | tail -1 | tr -dc 0-9; }
pick_volume() {
  best=/
  best_free=$(free_on /)
  if mountpoint -q /mnt; then
    local mnt_free
    mnt_free=$(free_on /mnt)
    if (( mnt_free > best_free )); then best=/mnt; best_free=$mnt_free; fi
  fi
}

# Work volume: the one with the most free space (/ or the temporary disk
# on /mnt when there is one).
pick_volume
log "Disk: $best_free GiB free on $best"
if (( best_free < min_free_gb )) && [[ "${LAB_SKIP_CLEANUP:-0}" != 1 ]]; then
  # Preinstalled SDKs the lab never uses (about 35 GiB, two minutes).
  start=$(date +%s)
  sudo rm -rf /usr/share/dotnet /usr/local/lib/android /opt/ghc /usr/local/.ghcup \
    /opt/hostedtoolcache/CodeQL /usr/share/swift /usr/local/share/powershell \
    /usr/local/share/chromium /opt/microsoft /opt/google /usr/lib/jvm \
    /usr/local/julia* /opt/az /usr/share/miniconda || true
  sudo docker image prune --all --force >/dev/null 2>&1 || true
  pick_volume
  log "Cleanup took $(( $(date +%s) - start )) s: $best_free GiB free on $best"
fi
(( best_free >= min_free_gb )) || fail "only $best_free GiB free on $best, $min_free_gb GiB needed"
work=${best%/}/ostena-lab
sudo mkdir -p "$work"
sudo chown "$(id -u):$(id -g)" "$work"
log "Work directory: $work"

# Lab tools, all under free licences and outside the product: QEMU (GPL),
# xorriso (GPL), wimtools (GPL/LGPL), nftables (GPL), socat (GPL), python3
# (PSF).
start=$(date +%s)
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  qemu-system-x86 qemu-utils xorriso wimtools nftables socat >/dev/null
log "Packages installed in $(( $(date +%s) - start )) s: $(qemu-system-x86_64 --version | head -1)"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "LAB_WORK=$work" >>"$GITHUB_ENV"
fi
echo "$work"
