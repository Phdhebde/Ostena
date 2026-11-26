#!/usr/bin/env bash
# Silent installation of the agent MSI on a lab machine (ADR-0024), by
# default the gateway gw2016 (Windows Server 2016, isolated zone without any
# inbound flow): the same checks as on the CI runners
# (tests/packaging/windows-msi.ps1), on the oldest supported Windows.
#
#   lab/agent-msi.sh <directory of the ostena-test-signed artifact> [machine]
#
# Run on the lab host once the lab is up (lab.yml, input `command`), with
# LAB_WORK set. The machine fetches the files from the lab control service
# (http://<segment gateway>:8089/files/), the only flow it may open besides
# the core. No core answers in the lab yet: the agent is installed without
# enrolment and its link stays "non connecté", retrying towards the host,
# which is what a gateway looks like before its core is reachable.
set -euo pipefail

SIGNED=$(cd "${1:?directory of the ostena-test-signed artifact}" && pwd)
VM=${2:-gw2016}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
: "${LAB_WORK:?LAB_WORK must name the lab work directory (lab.yml sets it)}"
files="$LAB_WORK/state/files"
mkdir -p "$files"

echo "=== the package is the one release-sign signed (ADR-0017)"
chmod +x "$SIGNED/ostena"
"$SIGNED/ostena" release verify "$SIGNED/ostena-release.manifest" --key "$SIGNED/release-test.pub"
msi=$(find "$SIGNED" -maxdepth 1 -name 'ostena-agent-*-x64.msi' | head -1)
[ -n "$msi" ] || { echo "no MSI in $SIGNED" >&2; exit 1; }

echo "=== a root for this run (no ceremony: lab only)"
rootdir=$(mktemp -d)
trap 'rm -rf "$rootdir"' EXIT
"$SIGNED/ostena" ca root init --name "Ostena lab root" --days 2 \
    --out "$rootdir/a" --out "$rootdir/b" >/dev/null

install -m 0644 "$msi" "$files/ostena-agent.msi"
install -m 0644 "$rootdir/a/root.pem" "$files/ostena-lab-root.pem"
install -m 0644 "$root/tests/packaging/windows-msi.ps1" "$files/windows-msi.ps1"
install -m 0644 "$root/tests/agent/windows-pipe-nonadmin.ps1" "$files/windows-pipe-nonadmin.ps1"
certs=()
for cer in "$SIGNED"/*.cer; do
    install -m 0644 "$cer" "$files/$(basename "$cer")"
    certs+=("$(basename "$cer")")
done

# The segment gateway of the machine is the lab host: control service and,
# later, the core.
gateway=$(python3 -c 'import json, sys
lab = json.load(open(sys.argv[1]))
m = next(m for m in lab["machines"] if m["name"] == sys.argv[2])
print(lab["segments"][m["segment"]]["gateway"])' "$root/lab/machines.json" "$VM")

script=$(mktemp --suffix=.ps1)
trap 'rm -rf "$rootdir" "$script"' EXIT
cert_list=$(printf "'%s'," "${certs[@]}")
cat >"$script" <<EOF
\$ErrorActionPreference = 'Stop'
\$base = 'http://$gateway:8089/files'
\$dir = Join-Path \$env:TEMP 'ostena-lab'
New-Item -ItemType Directory -Force \$dir | Out-Null
\$certs = @(${cert_list%,})
foreach (\$f in @('ostena-agent.msi', 'ostena-lab-root.pem', 'windows-msi.ps1', 'windows-pipe-nonadmin.ps1') + \$certs) {
    Invoke-WebRequest -UseBasicParsing -Uri "\$base/\$f" -OutFile (Join-Path \$dir \$f)
}
Write-Host "Windows: \$((Get-CimInstance Win32_OperatingSystem).Caption) \$([Environment]::OSVersion.Version)"
& (Join-Path \$dir 'windows-msi.ps1') -Msi (Join-Path \$dir 'ostena-agent.msi') \`
    -CoreAddress '$gateway:8443' -RootCa (Join-Path \$dir 'ostena-lab-root.pem') \`
    -TrustCertificate (\$certs | ForEach-Object { Join-Path \$dir \$_ }) \`
    -PipeTest (Join-Path \$dir 'windows-pipe-nonadmin.ps1')
exit \$LASTEXITCODE
EOF

echo "=== silent installation on $VM"
LAB_EXEC_TIMEOUT_S=${LAB_EXEC_TIMEOUT_S:-900} "$root/lab/providers/qemu-ci/lab.sh" exec "$VM" "$script"
