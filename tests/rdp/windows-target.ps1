# Prepares a Windows CI runner as an RDP target for the tests of the RDP
# driver (crates/ostena-rdp/tests/windows_target.rs, ADR-0019): RDP on,
# NLA required, Restricted Admin allowed, remote session management (WTS
# API) allowed, one local administrator for every mode of the tests
# (delegation, Restricted Admin: the agent logs its sessions off, ADR-0026)
# with a random password and its profile already created, SMB signing
# required, and the target known by a DNS name of the lab mapped to
# 127.0.0.1 in the hosts file (the agent opens the management channel by
# that name once the scope control resolved it to the pinned address,
# ADR-0026; other.ostena.test maps to another loopback address, for the
# refusal). Writes the
# OSTENA_RDP_TARGET_* variables to $env:GITHUB_ENV, the password masked in
# the logs.
#
# Runs on a throwaway CI runner as Administrator, never on a workstation.
#
#   pwsh tests/rdp/windows-target.ps1
$ErrorActionPreference = 'Stop'
$Ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$Tcp = "$Ts\WinStations\RDP-Tcp"
$Policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

function Fail([string] $Message) {
    Write-Host "::error::$Message"
    Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -MaxEvents 20 -ErrorAction SilentlyContinue |
        Format-List TimeCreated, Id, Message
    exit 1
}

$User = 'ostena-rdp'

Set-Service -Name seclogon -StartupType Manual
Start-Service -Name seclogon
Write-Host "=== local administrator $User, random password"
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
# Administrators (S-1-5-32-544): Restricted Admin needs one, and so does
# the logoff of its sessions by the agent (WTS API).
Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $User -ErrorAction SilentlyContinue

Write-Host "=== profile of $User"
# The first logon of an account creates its profile (about 15 s on a CI
# runner), during the session itself otherwise. It is created here, by
# a logon that loads it, as on a target whose administrators have
# already logged on.
$Sid = (Get-LocalUser -Name $User).SID.Value
$Credential = New-Object System.Management.Automation.PSCredential(".\$User", $Secure)
Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/c', 'exit 0' `
    -Credential $Credential -LoadUserProfile -WorkingDirectory $env:SystemRoot `
    -WindowStyle Hidden -Wait
$UserProfile = $null
for ($i = 0; $i -lt 120 -and -not $UserProfile; $i++) {
    $Found = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$Sid'" -ErrorAction SilentlyContinue
    if ($Found -and $Found.LocalPath -and (Test-Path -LiteralPath (Join-Path $Found.LocalPath 'NTUSER.DAT'))) {
        $UserProfile = $Found
    } else {
        Start-Sleep -Seconds 1
    }
}
if (-not $UserProfile) { Fail "profile of $User missing after 120 s" }
Write-Host "profile: $($UserProfile.LocalPath)"

Write-Host '=== RDP: NLA required, Restricted Admin allowed'
Set-ItemProperty -Path $Ts -Name fDenyTSConnections -Value 0 -Type DWord
if (Test-Path $Policy) {
    Set-ItemProperty -Path $Policy -Name fDenyTSConnections -Value 0 -Type DWord
}
Set-ItemProperty -Path $Tcp -Name UserAuthentication -Value 1 -Type DWord
# 2: TLS (SSL), the only security layer the agent accepts.
Set-ItemProperty -Path $Tcp -Name SecurityLayer -Value 2 -Type DWord
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DisableRestrictedAdmin -Value 0 -Type DWord
# Remote session management (WTS API over RPC), used by the agent to log
# off the sessions of the account (ADR-0026).
Set-ItemProperty -Path $Ts -Name AllowRemoteRPC -Value 1 -Type DWord
Set-Service -Name TermService -StartupType Manual
Restart-Service -Name TermService -Force

Write-Host '=== name of the target, SMB signing required'
$Name = 'target.ostena.test'
$Hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
Add-Content -Path $Hosts -Value "`n127.0.0.1 $Name`n127.0.0.2 other.ostena.test" -Encoding ascii
# The NTLM loopback check refuses an authentication to this machine by
# another name than its own: the name of the lab is declared as one of
# its names (the same applies to an alias of a real target).
$Msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
New-ItemProperty -Path $Msv -Name BackConnectionHostNames -Value @($Name) -PropertyType MultiString -Force | Out-Null
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
Clear-DnsClientCache
$Resolved = (Resolve-DnsName -Name $Name -Type A -ErrorAction SilentlyContinue).IPAddress
if ($Resolved -ne '127.0.0.1') { Fail "$Name resolves to '$Resolved', not 127.0.0.1" }
Write-Host "$Name -> $Resolved, SMB signing required: $((Get-SmbServerConfiguration).RequireSecuritySignature)"

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

@(
    "OSTENA_RDP_TARGET_PORT=3389"
    "OSTENA_RDP_TARGET_NAME=$Name"
    # Qualified by the computer: the name of the lab is not the computer
    # name, from which the agent would otherwise take the domain of a
    # local account.
    "OSTENA_RDP_TARGET_USER=$($env:COMPUTERNAME)\$User"
    "OSTENA_RDP_TARGET_PASSWORD=$Password"
    "OSTENA_RDP_TARGET_SHA256=$Hash"
) | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
Write-Host "target ready: $Name, account $User"
