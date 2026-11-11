# Integration test of the agent service under the Windows SCM (ADR-0007).
# Runs on a CI runner as Administrator.
#
#   pwsh tests/agent/windows-service.ps1 -Binary target\release\ostena.exe
param([Parameter(Mandatory)] [string] $Binary)

$ErrorActionPreference = 'Stop'
$Service = 'OstenaAgent'
$Data = Join-Path $env:ProgramData 'Ostena'
$Config = Join-Path $Data 'ostena.toml'
$Log = Join-Path $Data 'state\agent.log'
$Exe = Join-Path $env:ProgramFiles 'Ostena\ostena.exe'

function Fail([string] $Message) {
    Write-Host "::error::$Message"
    if (Test-Path $Log) { Get-Content $Log -Tail 50 }
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager' } -MaxEvents 10 -ErrorAction SilentlyContinue |
        Format-List TimeCreated, Id, Message
    exit 1
}

function Wait-State([string] $State, [int] $Seconds) {
    for ($i = 0; $i -lt $Seconds; $i++) {
        $s = Get-Service $Service -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq $State) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

Write-Host '=== install (production configuration)'
New-Item -ItemType Directory -Force (Split-Path $Exe), $Data | Out-Null
Copy-Item $Binary $Exe -Force
@'
mode = "production"

[[logging.outputs]]
kind = "file"
path = 'C:\ProgramData\Ostena\state\agent.log'

[agent]
gateway_group = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
core_address = "core.invalid:8443"
tls_certificate = 'C:\ProgramData\Ostena\agent.crt'
tls_private_key = 'C:\ProgramData\Ostena\agent.key'
tls_core_ca = 'C:\ProgramData\Ostena\core-ca.pem'
replay_journal = 'C:\ProgramData\Ostena\state\replay.journal'
shutdown_grace_secs = 5
'@ | Set-Content -Encoding utf8NoBOM $Config
'not a real key' | Set-Content -Encoding ascii (Join-Path $Data 'agent.key')

& $Exe agent install --config $Config
if ($LASTEXITCODE -ne 0) { Fail "install failed ($LASTEXITCODE)" }
if (-not (Wait-State 'Running' 30)) { Fail 'the service did not start' }

Write-Host '=== service configuration'
$qc = sc.exe qc $Service | Out-String
if ($qc -notmatch 'NT SERVICE\\OstenaAgent') { Fail "account: $qc" }
$sid = sc.exe qsidtype $Service | Out-String
if ($sid -notmatch 'RESTRICTED') { Fail "SID type: $sid" }
$privs = sc.exe qprivs $Service | Out-String
if ($privs -notmatch 'SeChangeNotifyPrivilege') { Fail "required privileges: $privs" }
$failure = sc.exe qfailure $Service | Out-String
if (([regex]::Matches($failure, 'RESTART')).Count -ne 3) { Fail "failure actions: $failure" }
if ($failure -notmatch 'RESET_PERIOD \(in seconds\)\s*:\s*600') { Fail "reset period: $failure" }
Write-Host $qc, $sid, $privs, $failure

Write-Host '=== permissions'
icacls $Config
icacls (Join-Path $Data 'agent.key')
icacls (Join-Path $Data 'state')

Write-Host '=== status (administrator)'
$status = & $Exe agent status --config $Config | Out-String
Write-Host $status
if ($LASTEXITCODE -ne 0 -or $status -notmatch 'Groupe : 2f6c9a4e') { Fail 'status did not reach the control plane' }

Write-Host '=== control pipe refuses a non-administrator'
& (Join-Path $PSScriptRoot 'windows-pipe-nonadmin.ps1')
switch ($LASTEXITCODE) {
    0 { }
    1 { Fail 'a non-administrator reached the control pipe' }
    default { Fail "the non-administrator pipe test could not run ($LASTEXITCODE)" }
}

Write-Host '=== clean stop'
Stop-Service $Service
if (-not (Wait-State 'Stopped' 60)) { Fail 'the service did not stop' }
$logText = Get-Content $Log -Raw
foreach ($event in '"agent.stopped"', '"agent.sessions_closed"') {
    if ($logText -notmatch [regex]::Escape($event)) { Fail "no $event event" }
}

Write-Host '=== uninstall'
& $Exe agent uninstall
if ($LASTEXITCODE -ne 0) { Fail "uninstall failed ($LASTEXITCODE)" }
sc.exe query $Service | Out-Null
if ($LASTEXITCODE -ne 1060) { Fail "the service is still registered ($LASTEXITCODE)" }
& $Exe agent status --config $Config
if ($LASTEXITCODE -ne 4) { Fail "status after uninstall: exit $LASTEXITCODE, expected 4" }
Write-Host 'OK'
exit 0
