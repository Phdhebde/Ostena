#!/usr/bin/env bash
# Prepares a GitHub-hosted ubuntu-24.04 runner for the lab (ADR-0025):
# checks KVM, frees disk space, installs the lab tools and prints the
# measures (CPU, memory, disk) so that a failing run says why.
#
# Usage: lab/providers/qemu-ci/preflight.sh
# Variables:
#   LAB_MIN_FREE_GB  free space required on the work volume (default 40)
#   LAB_SKIP_CLEANUP 1 to keep the preinstalled SDKs (local runs)
set -euo pipefail

min_free_gb=${LAB_MIN_FREE_GB:-40}

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

df_line() { df -BG --output=target,avail "$1" | tail -1; }
log "Disk before cleanup: $(df_line /) | $(df_line /mnt 2>/dev/null || echo '/mnt absent')"

if [[ "${LAB_SKIP_CLEANUP:-0}" != 1 ]]; then
  # Preinstalled SDKs the lab never uses. Removed in the background-free
  # way (plain rm) so that the measure below is exact.
  start=$(date +%s)
  sudo rm -rf /usr/share/dotnet /usr/local/lib/android /opt/ghc /usr/local/.ghcup \
    /opt/hostedtoolcache/CodeQL /usr/share/swift /usr/local/share/powershell \
    /usr/local/share/chromium /opt/microsoft /opt/google /usr/lib/jvm \
    /usr/local/julia* /opt/az /usr/share/miniconda || true
  sudo docker image prune --all --force >/dev/null 2>&1 || true
  log "Cleanup took $(( $(date +%s) - start )) s"
fi
log "Disk after cleanup: $(df_line /) | $(df_line /mnt 2>/dev/null || echo '/mnt absent')"

# Work volume: the one with the most free space (usually the temporary
# disk mounted on /mnt).
best=/
best_free=$(df -BG --output=avail / | tail -1 | tr -dc 0-9)
if mountpoint -q /mnt; then
  mnt_free=$(df -BG --output=avail /mnt | tail -1 | tr -dc 0-9)
  if (( mnt_free > best_free )); then best=/mnt; best_free=$mnt_free; fi
fi
work=${best%/}/ostena-lab
sudo mkdir -p "$work"
sudo chown "$(id -u):$(id -g)" "$work"
log "Work directory: $work ($best_free GiB free)"
(( best_free >= min_free_gb )) || fail "only $best_free GiB free on $best, $min_free_gb GiB needed"

# Lab tools, all under free licences and outside the product: QEMU (GPL),
# xorriso (GPL), wimtools (GPL/LGPL), nftables (GPL), python3 (PSF).
start=$(date +%s)
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  qemu-system-x86 qemu-utils xorriso wimtools nftables >/dev/null
log "Packages installed in $(( $(date +%s) - start )) s: $(qemu-system-x86_64 --version | head -1)"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "LAB_WORK=$work" >>"$GITHUB_ENV"
fi
echo "$work"
