# Last step of a lab base image build (ADR-0025), run once at the first
# logon of the unattended installation (autounattend.xml).
#   1. installs boot.ps1 and the OstenaProvision startup task, which will run
#      the provisioning script of each machine created from this image;
#   2. generalizes the system with sysprep (new SID, name and password for
#      each machine) and powers it off: the provider then compresses the disk
#      into the base image.
param([Parameter(Mandatory = $true)][string]$Media)

$ErrorActionPreference = 'Stop'
$root = 'C:\Ostena'
New-Item -ItemType Directory -Force -Path $root | Out-Null
$log = Join-Path $root 'base.log'
function Write-Log([string]$Message) {
    $line = '{0} {1}' -f (Get-Date).ToUniversalTime().ToString('o'), $Message
    Add-Content -Path $log -Value $line
    Write-Host $line
    # The build machine has no network: its first serial port, a file on
    # the host, is how the provider follows (and fails) the build.
    try {
        $port = New-Object System.IO.Ports.SerialPort 'COM1', 115200
        $port.Open(); $port.WriteLine($line); $port.Close()
    } catch { }
}

try {
    Write-Log "base: $([Environment]::OSVersion.VersionString)"

    # Quiet, predictable guests: high performance plan, no hibernation file.
    powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c | Out-Null
    powercfg.exe /hibernate off | Out-Null

    # No automatic update attempt: the lab has no Internet access.
    $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    New-Item -Path $wu -Force | Out-Null
    Set-ItemProperty -Path $wu -Name NoAutoUpdate -Value 1 -Type DWord

    Copy-Item -Path (Join-Path $Media 'boot.ps1') -Destination (Join-Path $root 'boot.ps1') -Force

    # Startup task, as SYSTEM, without time limit: boot.ps1 waits for the end
    # of the out-of-box experience, then runs the machine's provision.ps1.
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File $root\boot.ps1"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName 'OstenaProvision' -Action $action -Trigger $trigger `
        -Settings $settings -Principal $principal -Force | Out-Null
    Write-Log 'base: OstenaProvision task registered'

    # Forget the build-time logon: no stored password left in the image.
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty -Path $winlogon -Name AutoAdminLogon -Value '0'
    Remove-ItemProperty -Path $winlogon -Name DefaultPassword -ErrorAction SilentlyContinue

    # Only the sysprep answer file may drive the next out-of-box experience:
    # remove the copies of the installation answer file Setup keeps.
    $sysprepAnswer = 'C:\Windows\System32\Sysprep\ostena-unattend.xml'
    Copy-Item -Path (Join-Path $Media 'sysprep-unattend.xml') -Destination $sysprepAnswer -Force
    foreach ($f in @('C:\Windows\Panther\unattend.xml', 'C:\Windows\Panther\Unattend\unattend.xml',
            'C:\Windows\Panther\autounattend.xml')) {
        Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
    }

    # Freed blocks reach the host (discard=unmap): smaller base image.
    try { Optimize-Volume -DriveLetter C -ReTrim -ErrorAction Stop } catch { Write-Log "base: retrim skipped: $_" }

    Write-Log 'base: running sysprep /generalize /oobe /shutdown'
    & "$env:SystemRoot\System32\Sysprep\sysprep.exe" /generalize /oobe /shutdown /quiet "/unattend:$sysprepAnswer"
} catch {
    Write-Log "base: FAILED: $_"
    throw
}
