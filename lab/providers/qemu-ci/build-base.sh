#!/usr/bin/env bash
# Builds the base image of one Windows version (ADR-0025): unattended
# installation from the checked evaluation ISO, then sysprep /generalize,
# then compression of the disk into $LAB_WORK/base/<image>.qcow2. The
# machine powers itself off at the end; this script only waits, follows the
# guest log on the first serial port and takes screenshots.
#
# Usage: lab/providers/qemu-ci/build-base.sh <image>
# Variables: LAB_WORK (see preflight.sh), LAB_BASE_TIMEOUT_MIN (default 90).
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

image=${1:?image name, e.g. ws2022}
timeout_min=${LAB_BASE_TIMEOUT_MIN:-90}
iso_dir=$LAB_WORK/iso
base_dir=$LAB_WORK/base
build=$LAB_WORK/build/$image
mkdir -p "$base_dir" "$build" "$LAB_RUN" "$LAB_STATE"

file=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["images"][sys.argv[2]]["file"])' "$LAB_DIR/images.json" "$image")
edition=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["images"][sys.argv[2]]["edition"])' "$LAB_DIR/images.json" "$image")
iso=$iso_dir/$file
[[ -f "$iso" ]] || fail "$iso missing: run fetch-iso.sh $image first"

# Index of the Server Core image of the wanted edition in install.wim.
mnt=$build/iso
mkdir -p "$mnt"
sudo mount -o loop,ro "$iso" "$mnt"
wiminfo "$mnt/sources/install.wim" >"$build/wiminfo.txt"
sudo umount "$mnt"
index=$(python3 - "$build/wiminfo.txt" "$edition" <<'EOF'
import re, sys
text, edition = open(sys.argv[1]).read(), sys.argv[2]
for block in re.split(r"\n(?=Index:)", text):
    fields = dict(re.findall(r"^([A-Za-z ]+?):\s*(.*)$", block, re.M))
    name = fields.get("Name", "")
    core = fields.get("Installation Type", "") == "Server Core" or (
        "Installation Type" not in fields and "Desktop" not in name)
    if "Index" in fields and core and edition.lower() in name.lower() and "desktop" not in name.lower():
        print(fields["Index"])
        break
EOF
)
[[ -n "$index" ]] || { cat "$build/wiminfo.txt"; fail "$image: no Server Core $edition image in install.wim"; }
log "$image: installing image $index ($(grep -A1 "^Index: *$index\$" "$build/wiminfo.txt" | sed -n 's/^Name: *//p'))"

# Configuration medium of the build: answer files and base scripts. The
# build password is drawn here and lives only in this medium and the image.
cfg=$build/cfg
rm -rf "$cfg"
mkdir -p "$cfg"
build_password=$(python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import labconfig; print(labconfig.password())' "$LAB_DIR/tools")
[[ -n "${GITHUB_ACTIONS:-}" ]] && echo "::add-mask::$build_password"
sed -e "s/@IMAGE_INDEX@/$index/" -e "s/@BUILD_PASSWORD@/$build_password/g" \
  "$LAB_DIR/guest/base/autounattend.xml" >"$cfg/autounattend.xml"
sed -e "s/@BUILD_PASSWORD@/$build_password/g" \
  "$LAB_DIR/guest/base/sysprep-unattend.xml" >"$cfg/sysprep-unattend.xml"
cp "$LAB_DIR/guest/base/ostena-base.ps1" "$LAB_DIR/guest/base/boot.ps1" "$cfg/"
xorriso -as mkisofs -quiet -V OSTENA_BASE -J -R -o "$build/cfg.iso" "$cfg"
rm -rf "$cfg"

disk=$build/install.qcow2
rm -f "$disk"
qemu-img create -q -f qcow2 "$disk" 40G
name=base-$image
rm -f "$LAB_RUN/$name.serial"
qemu_hw args "$name" 4096 2 "$disk"
args+=(
  -drive "file=$iso,media=cdrom,if=none,id=cd0,readonly=on" -device ide-cd,drive=cd0,bus=ide.1,bootindex=2
  -drive "file=$build/cfg.iso,media=cdrom,if=none,id=cd1,readonly=on" -device ide-cd,drive=cd1,bus=ide.2
  -nic none
)

start=$(date +%s)
"${args[@]}" &
qemu_pid=$!
deadline=$(( start + timeout_min * 60 ))
seen=0
status=running
while kill -0 "$qemu_pid" 2>/dev/null; do
  sleep 20
  if [[ -f "$LAB_RUN/$name.serial" ]]; then
    lines=$(wc -l <"$LAB_RUN/$name.serial")
    if (( lines > seen )); then
      sed -n "$((seen + 1)),${lines}p" "$LAB_RUN/$name.serial" | tr -d '\r' | sed "s/^/[$name] /"
      seen=$lines
    fi
    if grep -q 'base: FAILED' "$LAB_RUN/$name.serial"; then status=failed; break; fi
  fi
  now=$(date +%s)
  if (( (now - start) % 300 < 20 )); then screenshot "$name"; fi
  if (( now > deadline )); then status=timeout; break; fi
done
if [[ $status != running ]]; then
  screenshot "$name"
  sleep 2
  kill "$qemu_pid" 2>/dev/null || true
  wait "$qemu_pid" 2>/dev/null || true
  fail "$image: base build $status after $(( ($(date +%s) - start) / 60 )) min (screenshots in the diagnostics artifact)"
fi
wait "$qemu_pid" || fail "$image: QEMU exited with an error"
grep -q 'running sysprep' "$LAB_RUN/$name.serial" 2>/dev/null \
  || fail "$image: the machine powered off before sysprep"
installed=$(( $(date +%s) - start ))
log "$image: installed and generalized in $(( installed / 60 )) min $(( installed % 60 )) s"
timing "base_install_$image" "$installed"

start=$(date +%s)
qemu-img convert -O qcow2 -c -o compression_type=zstd "$disk" "$base_dir/$image.qcow2.part"
mv "$base_dir/$image.qcow2.part" "$base_dir/$image.qcow2"
rm -f "$disk" "$build/cfg.iso"
timing "base_compress_$image" "$(( $(date +%s) - start ))"
log "$image: base image $(du -h "$base_dir/$image.qcow2" | cut -f1) (virtual $(qemu-img info --output=json "$base_dir/$image.qcow2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"] // 2**30)') GiB)"
