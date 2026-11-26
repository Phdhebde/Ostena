# Provisioning of one lab machine (ADR-0025), run as SYSTEM at every boot by
# the OstenaProvision task (boot.ps1). It reads ostena-vm.json from the
# machine's configuration medium and plays the steps of its role, one after
# the other; a step that needs a reboot records the next step and restarts
# the machine itself. Progress and results go to the lab control service of
# the host (POST /report/<name>); once ready, the machine polls that service
# for commands (GET /task/<name>), so that the host never opens a connection
# to it (required for the isolated zone).
#
# Roles: dc (forest, AD CS, test accounts, keytab), member (domain join,
# Remote Desktop with a CA certificate), gateway (isolated zone, workgroup).
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Root = 'C:\Ostena'
$Cfg = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'ostena-vm.json') | ConvertFrom-Json
$StateFile = Join-Path $Root 'step.txt'
$LogFile = Join-Path $Root 'provision.log'

function Write-Log([string]$Message) {
    $line = '{0} {1}: {2}' -f (Get-Date).ToUniversalTime().ToString('o'), $Cfg.name, $Message
    Add-Content -Path $LogFile -Value $line
    try {
        $port = New-Object System.IO.Ports.SerialPort 'COM1', 115200
        $port.Open(); $port.WriteLine($line); $port.Close()
    } catch { }
}

function Send-Report([string]$State, [string]$Message, $Facts = $null) {
    $body = @{
        state   = $State
        step    = (Get-Step)
        message = $Message
        facts   = $Facts
        time    = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json -Depth 8 -Compress
    try {
        Invoke-RestMethod -UseBasicParsing -Method Post -TimeoutSec 15 -ContentType 'application/json; charset=utf-8' `
            -Uri "$($Cfg.control_url)/report/$($Cfg.name)" -Body $body | Out-Null
    } catch {
        Write-Log "report not delivered: $($_.Exception.Message)"
    }
}

function Get-Step {
    if (Test-Path -LiteralPath $StateFile) { return (Get-Content -LiteralPath $StateFile -Raw).Trim() }
    return 'init'
}

function Set-Step([string]$Step) {
    Set-Content -LiteralPath $StateFile -Value $Step
    Write-Log "next step: $Step"
}

function Restart-Self([string]$NextStep) {
    Set-Step $NextStep
    Send-Report 'running' "rebooting before step $NextStep"
    Restart-Computer -Force
    exit 0
}

function ConvertTo-Secure([string]$Text) { ConvertTo-SecureString -String $Text -AsPlainText -Force }

function Wait-Until([string]$What, [int]$Minutes, [scriptblock]$Test) {
    $deadline = (Get-Date).AddMinutes($Minutes)
    $last = ''
    while ($true) {
        try {
            $result = & $Test
            if ($result) { return $result }
        } catch { $last = $_.Exception.Message }
        if ((Get-Date) -gt $deadline) { throw "timed out after $Minutes min waiting for ${What}: $last" }
        Start-Sleep -Seconds 15
    }
}

function Get-CertFacts($Cert) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash($Cert.RawData)
    } finally { $sha.Dispose() }
    return @{
        subject = $Cert.Subject
        issuer  = $Cert.Issuer
        sha1    = $Cert.Thumbprint.ToLowerInvariant()
        sha256  = (($digest | ForEach-Object { $_.ToString('x2') }) -join '')
        not_after = $Cert.NotAfter.ToUniversalTime().ToString('o')
        der_base64 = [Convert]::ToBase64String($Cert.RawData)
    }
}

# ---------------------------------------------------------------- common

function Step-Init {
    Write-Log "init: $([Environment]::OSVersion.VersionString)"
    ([ADSI]'WinNT://./Administrator,user').SetPassword($Cfg.admin_password)

    $nic = Wait-Until 'a network adapter' 10 { Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1 }
    $index = $nic.ifIndex
    Set-NetIPInterface -InterfaceIndex $index -Dhcp Disabled
    $current = Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if (-not ($current | Where-Object IPAddress -eq $Cfg.ip)) {
        $current | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceIndex $index -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        New-NetIPAddress -InterfaceIndex $index -IPAddress $Cfg.ip -PrefixLength $Cfg.prefix `
            -DefaultGateway $Cfg.gateway | Out-Null
    }
    Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $Cfg.dns
    Write-Log "init: $($Cfg.ip)/$($Cfg.prefix) via $($Cfg.gateway), DNS $($Cfg.dns -join ',')"

    if ($Cfg.role -ne 'gateway') {
        # Diagnostics from the host; never in the isolated zone.
        Enable-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In' -ErrorAction SilentlyContinue
    }

    Wait-Until 'the lab control service' 10 {
        Invoke-RestMethod -UseBasicParsing -TimeoutSec 5 -Uri "$($Cfg.control_url)/ping" | Out-Null; $true
    } | Out-Null
    Send-Report 'running' 'network configured'

    if ($env:COMPUTERNAME -ne $Cfg.hostname.ToUpperInvariant()) {
        Rename-Computer -NewName $Cfg.hostname -Force
        Restart-Self 'role'
    }
    Set-Step 'role'
}

function Enable-RemoteDesktop {
    $ts = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    Set-ItemProperty -Path $ts -Name fDenyTSConnections -Value 0
    # Network Level Authentication (CredSSP) required, as in production.
    Set-ItemProperty -Path "$ts\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
}

# ---------------------------------------------------------------- dc

function Step-DcPromote {
    Send-Report 'running' 'installing AD DS and AD CS'
    Install-WindowsFeature -Name AD-Domain-Services, ADCS-Cert-Authority -IncludeManagementTools | Out-Null
    Import-Module ADDSDeployment
    Send-Report 'running' "creating the forest $($Cfg.domain.fqdn)"
    Install-ADDSForest -DomainName $Cfg.domain.fqdn -DomainNetbiosName $Cfg.domain.netbios `
        -SafeModeAdministratorPassword (ConvertTo-Secure $Cfg.dsrm_password) -InstallDns `
        -NoRebootOnCompletion -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
    Restart-Self 'dc-configure'
}

function Set-DomainUser([string]$Name, [string]$Password, [string]$Path) {
    $existing = Get-ADUser -Filter "SamAccountName -eq '$Name'" -ErrorAction SilentlyContinue
    $secure = ConvertTo-Secure $Password
    if ($existing) {
        Set-ADAccountPassword -Identity $Name -Reset -NewPassword $secure
        Enable-ADAccount -Identity $Name
    } else {
        New-ADUser -Name $Name -SamAccountName $Name -UserPrincipalName "$Name@$($Cfg.domain.fqdn)" `
            -Path $Path -AccountPassword $secure -Enabled $true -PasswordNeverExpires $true
    }
}

function Step-DcConfigure {
    Send-Report 'running' 'waiting for Active Directory'
    Import-Module ActiveDirectory
    $domain = Wait-Until 'Active Directory Web Services' 30 { Get-ADDomain }
    $base = $domain.DistinguishedName
    $ou = "OU=Ostena,$base"
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Ostena'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name 'Ostena' -Path $base -ProtectedFromAccidentalDeletion $false
    }
    if (-not (Get-ADGroup -Filter "Name -eq 'ostena-rdp-users'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name 'ostena-rdp-users' -GroupScope Global -GroupCategory Security -Path $ou
    }
    foreach ($account in $Cfg.accounts) {
        Set-DomainUser $account.name $account.password $ou
        foreach ($group in $account.groups) { Add-ADGroupMember -Identity $group -Members $account.name }
    }
    Write-Log "dc: $($Cfg.accounts.Count) test accounts ready"

    # Kerberos SPNEGO service account of the core (AES256 only) and its keytab.
    $svc = $Cfg.service
    Set-DomainUser $svc.name $svc.password $ou
    Set-ADUser -Identity $svc.name -KerberosEncryptionType AES256
    $out = Join-Path $Root 'out'
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    $keytab = Join-Path $out 'service.keytab'
    $principal = "$($svc.spn)@$($Cfg.domain.realm)"
    # Through cmd: in Windows PowerShell 5.1, redirected native stderr
    # would become a terminating error under ErrorActionPreference=Stop.
    & cmd.exe /c "ktpass.exe /out $keytab /princ $principal /mapuser $($Cfg.domain.netbios)\$($svc.name) /pass $($svc.password) /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /mapop set >NUL 2>&1"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $keytab)) { throw "ktpass failed ($LASTEXITCODE)" }
    Write-Log "dc: keytab written for $principal"

    # Name of the host (core under test) in the lab DNS.
    $zone = $Cfg.domain.fqdn
    # Fails harmlessly when the record already exists (step replayed).
    & cmd.exe /c "dnscmd.exe /recordadd $zone $($Cfg.bastion.name) A $($Cfg.bastion.ip) >NUL 2>&1"
    Write-Log "dc: DNS record $($Cfg.bastion.name).$zone -> $($Cfg.bastion.ip) (dnscmd exit $LASTEXITCODE)"

    # Enterprise root CA, ECDSA P-256 / SHA-256: issues the Remote Desktop
    # certificates of the members and the LDAPS certificate of this DC.
    $caConfig = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    if (-not (Get-ItemProperty -Path $caConfig -Name Active -ErrorAction SilentlyContinue)) {
        Send-Report 'running' 'installing the enterprise CA'
        Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName 'Ostena Lab Root CA' `
            -CryptoProviderName 'ECDSA_P256#Microsoft Software Key Storage Provider' -KeyLength 256 `
            -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 2 -Force | Out-Null
    }
    $caCert = Wait-Until 'the CA certificate' 10 {
        Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq 'CN=Ostena Lab Root CA, DC=lab, DC=ostena, DC=test' -or ($_.Subject -like 'CN=Ostena Lab Root CA*' -and $_.Subject -eq $_.Issuer) } | Select-Object -First 1
    }

    # LDAPS: the DC enrolls for its own certificate once the CA exists.
    $ldapsCert = Wait-Until 'the domain controller certificate' 15 {
        & certutil.exe -pulse | Out-Null
        $c = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
            $_.Issuer -eq $caCert.Subject -and $_.Subject -ne $caCert.Subject -and
            ($_.EnhancedKeyUsageList | Where-Object ObjectId -eq '1.3.6.1.5.5.7.3.1')
        } | Select-Object -First 1
        if (-not $c) {
            try { Get-Certificate -Template 'DomainController' -CertStoreLocation Cert:\LocalMachine\My | Out-Null } catch { }
        }
        $c
    }

    Send-Report 'ready' 'domain controller ready' @{
        fqdn       = "$($Cfg.hostname).$($Cfg.domain.fqdn)".ToLowerInvariant()
        domain_sid = $domain.DomainSID.Value
        ca         = (Get-CertFacts $caCert)
        ldaps      = (Get-CertFacts $ldapsCert)
        keytab_base64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($keytab))
        keytab_principal = $principal
    }
    Set-Step 'done'
}

# ---------------------------------------------------------------- member

function Step-MemberJoin {
    Enable-RemoteDesktop
    $local = $Cfg.local_account
    if (-not (Get-LocalUser -Name $local.name -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $local.name -Password (ConvertTo-Secure $local.password) -PasswordNeverExpires `
            -AccountNeverExpires | Out-Null
    } else {
        Set-LocalUser -Name $local.name -Password (ConvertTo-Secure $local.password)
    }
    Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $local.name -ErrorAction SilentlyContinue

    Send-Report 'running' "joining $($Cfg.domain.fqdn)"
    $cred = New-Object System.Management.Automation.PSCredential("$($Cfg.domain.netbios)\Administrator", (ConvertTo-Secure $Cfg.admin_password))
    Wait-Until "the domain $($Cfg.domain.fqdn)" 90 {
        Add-Computer -DomainName $Cfg.domain.fqdn -Credential $cred -Force -ErrorAction Stop -WarningAction SilentlyContinue
        $true
    } | Out-Null
    Restart-Self 'member-finalize'
}

function Step-MemberFinalize {
    Wait-Until 'the secure channel' 20 { Test-ComputerSecureChannel } | Out-Null
    $group = "$($Cfg.domain.netbios)\ostena-rdp-users"
    Wait-Until "the group $group" 60 {
        $members = Get-LocalGroupMember -Group 'Remote Desktop Users' | Where-Object Name -eq $group
        if (-not $members) { Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $group -ErrorAction Stop }
        $true
    } | Out-Null

    # Machine certificate from the enterprise CA, used by Remote Desktop.
    Send-Report 'running' 'requesting the machine certificate'
    $cert = Wait-Until 'a machine certificate from the enterprise CA' 60 {
        $c = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
            $_.Issuer -like 'CN=Ostena Lab Root CA*' -and
            ($_.EnhancedKeyUsageList | Where-Object ObjectId -eq '1.3.6.1.5.5.7.3.1')
        } | Select-Object -First 1
        if (-not $c) {
            # Fetches the enterprise roots from the directory, then enrolls.
            & certutil.exe -pulse | Out-Null
            Get-Certificate -Template 'Machine' -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop | Out-Null
        }
        $c
    }
    $setting = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"
    Set-CimInstance -InputObject $setting -Property @{ SSLCertificateSHA1Hash = $cert.Thumbprint } | Out-Null
    Write-Log "member: Remote Desktop uses $($cert.Thumbprint)"

    Send-Report 'ready' 'member ready' @{
        fqdn = "$($Cfg.hostname).$($Cfg.domain.fqdn)".ToLowerInvariant()
        os   = [Environment]::OSVersion.Version.ToString()
        rdp  = (Get-CertFacts $cert)
    }
    Set-Step 'done'
}

# ---------------------------------------------------------------- gateway

function Step-Gateway {
    # Workgroup machine, Remote Desktop and file sharing off (defaults);
    # the Windows firewall keeps blocking inbound traffic.
    Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow
    Send-Report 'ready' 'gateway ready' @{
        os = [Environment]::OSVersion.Version.ToString()
    }
    Set-Step 'done'
}

# ---------------------------------------------------------------- commands

# Pull loop: the host queues PowerShell scripts, the machine fetches them.
function Start-TaskLoop {
    $ErrorActionPreference = 'Continue'
    Write-Log 'polling the control service for commands'
    $work = Join-Path $Root 'tasks'
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    while ($true) {
        try {
            $task = Invoke-RestMethod -UseBasicParsing -TimeoutSec 15 -Uri "$($Cfg.control_url)/task/$($Cfg.name)"
            if ($task -and $task.id) {
                $file = Join-Path $work "$($task.id).ps1"
                Set-Content -LiteralPath $file -Value $task.script -Encoding UTF8
                $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $file 2>&1 | Out-String
                $code = $LASTEXITCODE
                $body = @{ exit_code = $code; output = $output } | ConvertTo-Json -Compress
                Invoke-RestMethod -UseBasicParsing -Method Post -TimeoutSec 15 -ContentType 'application/json; charset=utf-8' `
                    -Uri "$($Cfg.control_url)/result/$($Cfg.name)/$($task.id)" -Body $body | Out-Null
                continue
            }
        } catch { }
        Start-Sleep -Seconds 3
    }
}

# ---------------------------------------------------------------- main

try {
    Write-Log "provision: step $(Get-Step)"
    while ($true) {
        $step = Get-Step
        if ($step -eq 'init') { Step-Init; continue }
        if ($step -eq 'role') {
            switch ($Cfg.role) {
                'dc' { Set-Step 'dc-promote' }
                'member' { Set-Step 'member-join' }
                'gateway' { Set-Step 'gateway' }
                default { throw "unknown role $($Cfg.role)" }
            }
            continue
        }
        switch ($step) {
            'dc-promote' { Step-DcPromote }
            'dc-configure' { Step-DcConfigure }
            'member-join' { Step-MemberJoin }
            'member-finalize' { Step-MemberFinalize }
            'gateway' { Step-Gateway }
            'done' { break }
            default { throw "unknown step $step" }
        }
        if ((Get-Step) -eq 'done') { break }
    }
    # Secrets of the run are no longer needed on the disk.
    Remove-Item -LiteralPath (Join-Path $PSScriptRoot 'ostena-vm.json') -Force -ErrorAction SilentlyContinue
} catch {
    Write-Log "FAILED at step $(Get-Step): $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)"
    Send-Report 'error' "step $(Get-Step): $($_.Exception.Message)"
}
Start-TaskLoop
