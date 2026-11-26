# Silent installation of the agent MSI (ADR-0024), as an administrator or
# SYSTEM: on the CI runners (windows-2022, windows-2025, PowerShell 7) and in
# the lab (Windows Server 2016, Windows PowerShell 5.1: keep this script
# compatible with both).
#
#   tests/packaging/windows-msi.ps1 -Msi ostena-agent-0.0.0-x64.msi `
#       -CoreAddress 127.0.0.1:4433 -RootCa root.pem [-IdentityDir dir] `
#       [-ExpectConnected] [-TrustCertificate a.cer,b.cer]
#
# Checks: the Authenticode signature of the package (and of ostena.exe),
# `msiexec /qn` with the properties on the command line, the service
# (delayed automatic start, bounded restarts, virtual account), `status`, no
# listening port of the agent (dial-back only), the control pipe refused to
# a non-administrator, a repair that changes nothing, then `msiexec /x`
# (service and program removed, configuration kept).
param(
    [Parameter(Mandatory)] [string] $Msi,
    [Parameter(Mandatory)] [string] $CoreAddress,
    [Parameter(Mandatory)] [string] $RootCa,
    [string] $Group = '2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6',
    # agent.crt and agent.key already issued (test core): no enrolment.
    [string] $IdentityDir = '',
    [string] $TokenFile = '',
    [switch] $ExpectConnected,
    # Test certificates to trust on this machine before checking signatures.
    [string[]] $TrustCertificate = @(),
    [string] $PipeTest = (Join-Path $PSScriptRoot '..\agent\windows-pipe-nonadmin.ps1')
)

$ErrorActionPreference = 'Stop'
# ostena writes UTF-8; without a console (lab channel) this may not apply.
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
$Service = 'OstenaAgent'
$Data = Join-Path $env:ProgramData 'Ostena'
$Exe = Join-Path $env:ProgramFiles 'Ostena\ostena.exe'
$Log = Join-Path $Data 'state\agent.log'
$MsiLog = Join-Path $env:TEMP 'ostena-msi.log'
$Msi = (Resolve-Path $Msi).Path
$RootCa = (Resolve-Path $RootCa).Path

function Fail([string] $Message) {
    Write-Host "::error::$Message"
    foreach ($f in (Join-Path $Data 'setup.log'), $Log) {
        if (Test-Path $f) { Write-Host "--- $f"; Get-Content $f -Tail 40 }
    }
    if (Test-Path $MsiLog) {
        Write-Host "--- $MsiLog (errors)"
        Select-String -Path $MsiLog -Pattern 'Return value 3|error|CustomAction' | Select-Object -Last 30 | ForEach-Object { $_.Line }
    }
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

# msiexec shows a modal usage box, even with /qn, when its command line is
# wrong: never wait for it forever.
function Invoke-Msiexec([string[]] $Arguments) {
    $p = Start-Process -FilePath msiexec.exe -ArgumentList $Arguments -PassThru
    $null = $p.Handle # keeps the exit code readable once the process is gone
    if (-not $p.WaitForExit(600000)) {
        $p.Kill()
        Fail "msiexec $($Arguments[0]) did not finish in 10 minutes"
    }
    return $p.ExitCode
}

# SHA-256 of the first certificate of a PEM file, in hexadecimal: what the
# ceremony record shows.
function Get-PemFingerprint([string] $Path) {
    $text = Get-Content -Raw $Path
    $b64 = [regex]::Match($text, '-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', 'Singleline').Groups[1].Value -replace '\s', ''
    $der = [Convert]::FromBase64String($b64)
    $sha = [Security.Cryptography.SHA256]::Create()
    return (($sha.ComputeHash($der) | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-AgentPid {
    return [int](Get-CimInstance Win32_Service -Filter "Name='$Service'").ProcessId
}

Write-Host '=== Authenticode signatures (test certificates of this CI run)'
foreach ($cer in $TrustCertificate) {
    # LocalMachine: no confirmation dialog, unlike CurrentUser\Root.
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
}
if ($TrustCertificate.Count -gt 0) {
    $sig = Get-AuthenticodeSignature $Msi
    Write-Host "MSI: $($sig.Status), $($sig.SignerCertificate.Subject), key $($sig.SignerCertificate.PublicKey.Oid.FriendlyName)"
    if ($sig.Status -ne 'Valid') { Fail "MSI signature: $($sig.Status) $($sig.StatusMessage)" }
    if ($sig.SignerCertificate.PublicKey.Oid.Value -ne '1.2.840.10045.2.1') { Fail 'the MSI is not signed with an ECDSA key' }
}

Write-Host '=== listening ports before installation'
$before = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" })

Write-Host '=== silent installation'
if ($IdentityDir) {
    # An identity issued by the test core, where enrolment would write it.
    New-Item -ItemType Directory -Force (Join-Path $Data 'state') | Out-Null
    Copy-Item (Join-Path $IdentityDir 'agent.crt'), (Join-Path $IdentityDir 'agent.key') (Join-Path $Data 'state') -Force
}
$fingerprint = Get-PemFingerprint $RootCa
Write-Host "root fingerprint: $fingerprint"
$arguments = @('/i', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$MsiLog`"",
    "COREADDRESS=$CoreAddress", "GATEWAYGROUP=$Group",
    "ROOTCAFILE=`"$RootCa`"", "ROOTFINGERPRINT=$fingerprint")
if ($TokenFile) { $arguments += "ENROLLTOKENFILE=`"$TokenFile`"" }
$code = Invoke-Msiexec $arguments
if ($code -ne 0) { Fail "msiexec /i: exit $code" }
if (-not (Wait-State 'Running' 30)) { Fail 'the service did not start' }

Write-Host '=== files and service'
if (-not (Test-Path $Exe)) { Fail "$Exe not installed" }
if ($TrustCertificate.Count -gt 0) {
    $sig = Get-AuthenticodeSignature $Exe
    Write-Host "ostena.exe: $($sig.Status), $($sig.SignerCertificate.Subject)"
    if ($sig.Status -ne 'Valid') { Fail "ostena.exe signature: $($sig.Status) $($sig.StatusMessage)" }
}
$config = Get-Content -Raw (Join-Path $Data 'ostena.toml')
if ($config -notmatch 'mode = "production"') { Fail "configuration not in production mode: $config" }
if ($config -match '\[agent\.ssh\]') { Fail 'the configuration written by setup has an SSH server' }
$qc = sc.exe qc $Service | Out-String
Write-Host $qc
if ($qc -notmatch 'START_TYPE\s*:\s*2\s+AUTO_START\s+\(DELAYED\)') { Fail "start type: $qc" }
if ($qc -notmatch 'NT SERVICE\\OstenaAgent') { Fail "account: $qc" }
if ($qc -notmatch [regex]::Escape($Exe)) { Fail "binary path: $qc" }
$failure = sc.exe qfailure $Service | Out-String
if (([regex]::Matches($failure, 'RESTART')).Count -ne 3) { Fail "failure actions: $failure" }
if ((sc.exe qsidtype $Service | Out-String) -notmatch 'RESTRICTED') { Fail 'SID type' }
$setupLog = Get-Content -Raw -Encoding UTF8 (Join-Path $Data 'setup.log')
if ($setupLog -notmatch 'Certificat de la racine install') { Fail "setup.log: $setupLog" }

Write-Host '=== status (administrator)'
$connected = $false
for ($i = 0; $i -lt 30; $i++) {
    $status = & $Exe agent status | Out-String
    if ($LASTEXITCODE -ne 0) { Fail "status: exit $LASTEXITCODE`n$status" }
    if ($status -match 'Core : connect.{1,2} \(') { $connected = $true; break }
    if (-not $ExpectConnected) { break }
    Start-Sleep -Seconds 1
}
Write-Host $status
if ($ExpectConnected -and -not $connected) { Fail 'the agent did not connect to the core' }

Write-Host '=== no listening port (dial-back only)'
$agentPid = Get-AgentPid
$listening = @(Get-NetTCPConnection -State Listen -OwningProcess $agentPid -ErrorAction SilentlyContinue)
$udp = @(Get-NetUDPEndpoint -OwningProcess $agentPid -ErrorAction SilentlyContinue)
$after = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" })
$new = @($after | Where-Object { $before -notcontains $_ })
Write-Host "agent pid $agentPid; TCP listening: $($listening.Count); UDP endpoints: $(($udp | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }) -join ', ')"
Write-Host "new TCP listeners on the host since installation: $($new -join ', ')"
if ($listening.Count -ne 0) { Fail "the agent listens on TCP: $(($listening | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }) -join ', ')" }
# The QUIC client socket of the link to the core, nothing else: a client
# endpoint (no server configuration), on an ephemeral port.
if ($udp.Count -gt 1) { Fail "the agent holds $($udp.Count) UDP sockets" }
foreach ($u in $udp) { if ($u.LocalPort -lt 1024) { Fail "UDP socket on a well-known port: $($u.LocalPort)" } }

Write-Host '=== control pipe refuses a non-administrator'
& $PipeTest
switch ($LASTEXITCODE) {
    0 { }
    1 { Fail 'a non-administrator reached the control pipe' }
    default { Fail "the non-administrator pipe test could not run ($LASTEXITCODE)" }
}

# A repair with properties: /i with REINSTALL (msiexec /f ignores the
# properties of its command line).
Write-Host '=== repair: setup again, nothing changes'
$configBefore = Get-FileHash (Join-Path $Data 'ostena.toml')
$code = Invoke-Msiexec @('/i', "`"$Msi`"", 'REINSTALL=ALL', 'REINSTALLMODE=omus', '/qn', '/norestart', '/l*v', "`"$MsiLog`"",
    "COREADDRESS=$CoreAddress", "GATEWAYGROUP=$Group")
if ($code -ne 0) { Fail "msiexec /f: exit $code" }
if (-not (Wait-State 'Running' 30)) { Fail 'the service is not running after a repair' }
if ((Get-FileHash (Join-Path $Data 'ostena.toml')).Hash -ne $configBefore.Hash) { Fail 'the repair rewrote the configuration' }

Write-Host '=== a conflicting core address is refused, the agent is left as it was'
$code = Invoke-Msiexec @('/i', "`"$Msi`"", 'REINSTALL=ALL', 'REINSTALLMODE=omus', '/qn', '/norestart', '/l*v', "`"$MsiLog`"",
    'COREADDRESS=elsewhere.invalid:8443', "GATEWAYGROUP=$Group")
if ($code -eq 0) { Fail 'a repair with another core address succeeded' }
Write-Host "refused as expected (exit $code)"
if (-not (Test-Path $Exe)) { Fail 'the failed repair removed ostena.exe' }
if (-not (Wait-State 'Running' 30)) { Fail 'the failed repair stopped or removed the service' }

Write-Host '=== silent removal'
$code = Invoke-Msiexec @('/x', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$MsiLog`"")
if ($code -ne 0) { Fail "msiexec /x: exit $code" }
sc.exe query $Service | Out-Null
if ($LASTEXITCODE -ne 1060) { Fail "the service is still registered ($LASTEXITCODE)" }
if (Test-Path $Exe) { Fail "$Exe left behind" }
if (-not (Test-Path (Join-Path $Data 'ostena.toml'))) { Fail 'the configuration was not kept' }
Write-Host 'OK'
exit 0
