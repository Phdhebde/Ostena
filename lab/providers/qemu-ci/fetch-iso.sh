#!/usr/bin/env bash
# Downloads one evaluation ISO listed in lab/images.json and checks its
# SHA-256. A mismatch removes the file and fails: nothing is ever used
# unchecked.
#
# Usage: lab/providers/qemu-ci/fetch-iso.sh <image> <dest-dir>
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
lab=$(cd "$here/../.." && pwd)
image=${1:?image name, e.g. ws2022}
dest=${2:?destination directory}

field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["images"][sys.argv[2]][sys.argv[3]])' "$lab/images.json" "$image" "$1"; }
url=$(field url)
file=$(field file)
want=$(field sha256)

mkdir -p "$dest"
iso="$dest/$file"
start=$(date +%s)
if [[ ! -f "$iso" ]]; then
  curl --fail --location --silent --show-error --retry 5 --retry-delay 10 \
    --connect-timeout 30 --output "$iso.part" "$url"
  mv "$iso.part" "$iso"
fi
got=$(sha256sum "$iso" | cut -d' ' -f1)
size=$(( $(stat -c %s "$iso") / 1024 / 1024 ))
if [[ "$got" != "$want" ]]; then
  rm -f "$iso"
  printf '::error title=ISO checksum::%s: SHA-256 %s, expected %s (%s MiB)\n' "$image" "$got" "$want" "$size"
  exit 1
fi
printf '[fetch-iso] %s: %s MiB in %s s, SHA-256 verified (%s)\n' "$image" "$size" "$(( $(date +%s) - start ))" "$got"
