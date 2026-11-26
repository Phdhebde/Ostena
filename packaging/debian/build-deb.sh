#!/usr/bin/env bash
# Builds the .deb of the gateway agent (ADR-0024) for Debian 12 and 13 with
# dpkg-deb only, offline, from the static (musl) release binary.
#
#   packaging/debian/build-deb.sh <ostena (x86_64 musl)> <output directory>
#
# Reproducible for a given binary and commit: owners root:root, file times
# set to SOURCE_DATE_EPOCH (the commit time by default), xz compression.
set -euo pipefail

bin=${1:?path to the static ostena binary}
out=${2:?output directory}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' "$root/Cargo.toml")
[ -n "$version" ] || { echo "workspace version not found" >&2; exit 1; }
# Debian sorts "~" before anything: 1.0.0-rc.1 becomes 1.0.0~rc.1.
version=${version/-/\~}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct 2>/dev/null || date +%s)}
export SOURCE_DATE_EPOCH

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
pkg="$work/pkg"
doc="$pkg/usr/share/doc/ostena-agent"
install -d -m 0755 "$pkg/DEBIAN" "$pkg/usr/bin" "$doc"
install -m 0755 "$bin" "$pkg/usr/bin/ostena"
{
    cat "$here/copyright"
    sed -e 's/^$/./' -e 's/^/ /' "$root/LICENSE"
} >"$doc/copyright"
chmod 0644 "$doc/copyright"
for script in postinst prerm postrm; do
    install -m 0755 "$here/$script" "$pkg/DEBIAN/$script"
done
size=$(du -sk --exclude=DEBIAN "$pkg" | cut -f1)
sed -e "s/@VERSION@/$version/" -e "s/@SIZE@/$size/" "$here/control" >"$pkg/DEBIAN/control"
(cd "$pkg" && find usr -type f -print0 | sort -z | xargs -0 md5sum) >"$pkg/DEBIAN/md5sums"
chmod 0644 "$pkg/DEBIAN/control" "$pkg/DEBIAN/md5sums"
find "$pkg" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

mkdir -p "$out"
deb="$out/ostena-agent_${version}_amd64.deb"
rm -f "$deb"
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$deb" >/dev/null
echo "$deb"
