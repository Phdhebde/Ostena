# Prepares a Windows CI runner as an RDP target for the tests of the RDP
# driver (crates/ostena-rdp/tests/windows_target.rs, ADR-0019): RDP on,
# NLA required, Restricted Admin allowed, a local administrator with a
# random password. Writes the OSTENA_RDP_TARGET_* variables to
# $env:GITHUB_ENV, the password masked in the logs.
#
# Runs on a throwaway CI runner as Administrator, never on a workstation.
#
#   pwsh tests/rdp/windows-target.ps1
$ErrorActionPreference = 'Stop'
$User = 'ostena-rdp'
$Ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$Tcp = "$Ts\WinStations\RDP-Tcp"
$Policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

function Fail([string] $Message) {
    Write-Host "::error::$Message"
    Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -MaxEvents 20 -ErrorAction SilentlyContinue |
        Format-List TimeCreated, Id, Message
    exit 1
}

Write-Host '=== local administrator, random password'
$Bytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(24)
$Random = [Convert]::ToBase64String($Bytes).Replace('+', 'x').Replace('/', 'y').Replace('=', '')
# Upper case, lower case, digit and symbol: the complexity policy.
$Password = "Aa1-$Random"
Write-Host "::add-mask::$Password"
$Secure = ConvertTo-SecureString $Password -AsPlainText -Force
if (Get-LocalUser -Name $User -ErrorAction SilentlyContinue) {
    Set-LocalUser -Name $User -Password $Secure
} else {
    New-LocalUser -Name $User -Password $Secure -PasswordNeverExpires -AccountNeverExpires | Out-Null
}
# Administrators (S-1-5-32-544): Restricted Admin needs one.
Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $User -ErrorAction SilentlyContinue

Write-Host '=== RDP: NLA required, Restricted Admin allowed'
Set-ItemProperty -Path $Ts -Name fDenyTSConnections -Value 0 -Type DWord
if (Test-Path $Policy) {
    Set-ItemProperty -Path $Policy -Name fDenyTSConnections -Value 0 -Type DWord
}
Set-ItemProperty -Path $Tcp -Name UserAuthentication -Value 1 -Type DWord
# 2: TLS (SSL), the only security layer the agent accepts.
Set-ItemProperty -Path $Tcp -Name SecurityLayer -Value 2 -Type DWord
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DisableRestrictedAdmin -Value 0 -Type DWord
Set-Service -Name TermService -StartupType Manual
Restart-Service -Name TermService -Force

Write-Host '=== listener and certificate'
$Hash = $null
for ($i = 0; $i -lt 60 -and -not $Hash; $i++) {
    Start-Sleep -Seconds 1
    $Listening = Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue
    if (-not $Listening) { continue }
    $Setting = Get-CimInstance -Namespace 'root/cimv2/TerminalServices' -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"
    $Thumbprint = $Setting.SSLCertificateSHA1Hash
    if (-not $Thumbprint) { continue }
    $Certificate = Get-Item -Path "Cert:\LocalMachine\Remote Desktop\$Thumbprint" -ErrorAction SilentlyContinue
    if (-not $Certificate) { continue }
    $Hash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($Certificate.RawData)).ToLowerInvariant()
    Write-Host "certificate: $($Certificate.Subject), SHA-256 $Hash"
}
if (-not $Hash) { Fail 'RDP listener or certificate missing after 60 s' }

$Name = $env:COMPUTERNAME.ToLowerInvariant()
@(
    "OSTENA_RDP_TARGET_PORT=3389"
    "OSTENA_RDP_TARGET_NAME=$Name"
    "OSTENA_RDP_TARGET_USER=$User"
    "OSTENA_RDP_TARGET_PASSWORD=$Password"
    "OSTENA_RDP_TARGET_SHA256=$Hash"
) | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
Write-Host "target ready: $Name, account $User"
