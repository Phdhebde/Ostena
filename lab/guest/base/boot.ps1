# Startup task of every lab machine (ADR-0025), baked into the base image.
# Waits for the end of the out-of-box experience, copies the machine's
# configuration medium (the volume holding ostena-vm.json) and runs its
# provision.ps1. All the provisioning logic lives on that medium, so that
# changing it never invalidates the cached base images.
$ErrorActionPreference = 'Continue'
$root = 'C:\Ostena'
New-Item -ItemType Directory -Force -Path $root | Out-Null
$log = Join-Path $root 'boot.log'

function Write-Boot([string]$Message) {
    $line = '{0} boot: {1}' -f (Get-Date).ToUniversalTime().ToString('o'), $Message
    Add-Content -Path $log -Value $line
    try {
        $port = New-Object System.IO.Ports.SerialPort 'COM1', 115200
        $port.Open(); $port.WriteLine($line); $port.Close()
    } catch { }
}

# The task also fires while Windows finishes specializing the image.
$setupState = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State'
while ((Get-ItemProperty -Path $setupState -ErrorAction SilentlyContinue).ImageState -ne 'IMAGE_STATE_COMPLETE') {
    Start-Sleep -Seconds 5
}

$cfg = Join-Path $root 'cfg'
$found = $null
for ($i = 0; $i -lt 120 -and -not $found; $i++) {
    foreach ($drive in Get-PSDrive -PSProvider FileSystem) {
        if (Test-Path -LiteralPath (Join-Path $drive.Root 'ostena-vm.json')) { $found = $drive.Root; break }
    }
    if (-not $found) { Start-Sleep -Seconds 5 }
}
if (-not $found) {
    Write-Boot 'no configuration medium (ostena-vm.json) found'
    exit 1
}
New-Item -ItemType Directory -Force -Path $cfg | Out-Null
Copy-Item -Path (Join-Path $found '*') -Destination $cfg -Recurse -Force
Write-Boot "configuration copied from $found"

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $cfg 'provision.ps1')
Write-Boot "provision.ps1 exited with $LASTEXITCODE"
