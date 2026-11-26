#!/usr/bin/env bash
# Builds the MSI of the gateway agent (ADR-0024) with wixl (msitools), on
# Linux, offline: `apt-get install wixl msitools` (Debian and Ubuntu
# archives) is the only prerequisite. wixl is a build tool: nothing of it is
# linked to or shipped with Ostena.
#
#   packaging/windows/build-msi.sh <ostena.exe> <output directory>
#
# The executable should already be signed (Authenticode): the MSI embeds it
# as is. The MSI itself is signed afterwards, on Windows (CI job msi-sign).
set -euo pipefail

exe=${1:?path to ostena.exe}
out=${2:?output directory}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

# MSI versions are numeric: major.minor.patch of the workspace version,
# without any pre-release suffix.
version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([0-9]*\.[0-9]*\.[0-9]*\).*"/\1/p' "$root/Cargo.toml")
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "workspace version not found" >&2; exit 1; }

mkdir -p "$out"
msi="$out/ostena-agent-$version-x64.msi"
rm -f "$msi"
exe_abs="$(cd "$(dirname "$exe")" && pwd)/$(basename "$exe")"
wixl --arch x64 \
    -D "Version=$version" \
    -D "Exe=$exe_abs" \
    -D "License=$root/LICENSE" \
    -o "$msi" "$here/ostena-agent.wxs"

# The tables that make the package what ADR-0024 says it is: the setup and
# removal run as deferred, non-impersonated actions (type 3090), the old
# version is removed right after InstallInitialize.
if command -v msiinfo >/dev/null; then
    actions=$(msiinfo export "$msi" CustomAction)
    sequence=$(msiinfo export "$msi" InstallExecuteSequence)
    grep -q $'^OstenaSetup\t3090\tOstenaExe\tagent setup ' <<<"$actions" \
        || { echo "OstenaSetup is not a deferred, non-impersonated action" >&2; exit 1; }
    grep -q $'^OstenaUninstall\t3090\tOstenaExe\tagent uninstall --quiet' <<<"$actions" \
        || { echo "OstenaUninstall is not a deferred, non-impersonated action" >&2; exit 1; }
    grep -q $'^RemoveExistingProducts\t\t1501' <<<"$sequence" \
        || { echo "RemoveExistingProducts is not right after InstallInitialize" >&2; exit 1; }
fi
echo "$msi"
