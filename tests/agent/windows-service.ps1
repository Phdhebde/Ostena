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
tls_certificate = 'C:\ProgramData\Ostena\state\agent.crt'
tls_private_key = 'C:\ProgramData\Ostena\state\agent.key'
tls_core_ca = 'C:\ProgramData\Ostena\core-ca.pem'
replay_journal = 'C:\ProgramData\Ostena\state\replay.journal'
shutdown_grace_secs = 5

[agent.ssh]
listen = ["127.0.0.1:2222"]
'@ | Set-Content -Encoding utf8NoBOM $Config
# The identity lives in the state directory, where the service may write
# (renewal).
New-Item -ItemType Directory -Force (Join-Path $Data 'state') | Out-Null
'not a real key' | Set-Content -Encoding ascii (Join-Path $Data 'state\agent.key')

& $Exe agent install --config $Config
if ($LASTEXITCODE -ne 0) { Fail "install failed ($LASTEXITCODE)" }
if (-not (Wait-State 'Running' 30)) { Fail 'the service did not start' }

Write-Host '=== service configuration'
$qc = sc.exe qc $Service | Out-String
if ($qc -notmatch 'NT SERVICE\\OstenaAgent') { Fail "account: $qc" }
if ($qc -notmatch 'START_TYPE\s*:\s*2\s+AUTO_START\s+\(DELAYED\)') { Fail "start type: $qc" }
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
$keyAcl = icacls (Join-Path $Data 'state\agent.key') | Out-String
Write-Host $keyAcl
# Read and delete: a renewal replaces the key.
if ($keyAcl -notmatch 'NT SERVICE\\OstenaAgent:\(R,D\)') { Fail "service rights on the key: $keyAcl" }
if ($keyAcl -match '\(I\)') { Fail "inherited entries on the key: $keyAcl" }
icacls (Join-Path $Data 'state')

Write-Host '=== native SSH server (ADR-0010): keys created by the service, listening, no handshake without identity'
foreach ($name in 'ssh_host_key', 'ssh_target_key') {
    $path = Join-Path $Data "state\$name"
    if (-not (Test-Path $path)) { Fail "$name not created" }
    $acl = icacls $path | Out-String
    Write-Host $acl
    if ($acl -notmatch 'NT SERVICE\\OstenaAgent:\(R,D\)') { Fail "service rights on ${name}: $acl" }
    if ($acl -match '\(I\)') { Fail "inherited entries on ${name}: $acl" }
    if ($acl -match 'Users|Everyone|Authenticated') { Fail "$name readable by others: $acl" }
}
# Without a core, no host certificate is pushed: the server accepts the
# connection and closes it before its identification, with an audit event.
$client = New-Object System.Net.Sockets.TcpClient
$client.Connect('127.0.0.1', 2222)
$stream = $client.GetStream()
$stream.ReadTimeout = 5000
$buffer = New-Object byte[] 14
try { $read = $stream.Read($buffer, 0, 14) }
catch { Fail "SSH server: connection left open or reset: $($_.Exception.Message)" }
$client.Close()
if ($read -ne 0) {
    Fail "SSH identification sent without a host identity: '$([System.Text.Encoding]::ASCII.GetString($buffer, 0, $read))'"
}
$refused = $false
foreach ($i in 1..20) {
    if ((Test-Path $Log) -and (Select-String -Path $Log -Pattern '"code":"SSH-E018".*"event":"ssh.connection_refused"' -Quiet)) {
        $refused = $true
        break
    }
    Start-Sleep -Milliseconds 500
}
if (-not $refused) { Fail 'no ssh.connection_refused (SSH-E018) for a connection without identity' }
$line = & $Exe agent ssh-key --config $Config --line --from 10.20.0.11 | Out-String
Write-Host $line
if ($LASTEXITCODE -ne 0 -or $line -notmatch '^restrict,from="10\.20\.0\.11" ecdsa-sha2-nistp256 ') { Fail "authorized_keys line: $line" }

Write-Host '=== status (administrator)'
$status = & $Exe agent status --config $Config | Out-String
Write-Host $status
if ($LASTEXITCODE -ne 0 -or $status -notmatch 'Groupe : 2f6c9a4e') { Fail 'status did not reach the control plane' }
if ($status -notmatch 'SSH : .* 127\.0\.0\.1:2222') { Fail 'status does not show the SSH server' }
if ($status -notmatch 'Identité SSH : pas encore reçue du core') { Fail 'status does not show the pending SSH identity' }

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
foreach ($event in '"agent.stopped"', '"agent.sessions_closed"', '"agent.ssh_stopped"') {
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
