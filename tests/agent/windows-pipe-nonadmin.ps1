# The agent control pipe must refuse a standard (non-administrator) user.
# Creates a temporary local user, opens the pipe while impersonating it, and
# expects access denied. Runs as Administrator; exit code 0 when refused,
# 1 when the pipe accepted the user, 2 when the test itself could not run.

$ErrorActionPreference = 'Stop'
$User = 'ostena-ci-user'
$Password = 'Os!' + [guid]::NewGuid().ToString('N')

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class OstenaLogon {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);
}
'@

# Not `net user /add`, which prompts for confirmation when the password is
# longer than 14 characters. Network logon is granted to Everyone, so the
# user needs no group membership.
$computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
try {
    $account = $computer.Create('User', $User)
    $account.SetPassword($Password)
    $account.SetInfo()
} catch {
    Write-Host "::error::cannot create the test user: $($_.Exception.Message)"
    exit 2
}
try {
    $token = [IntPtr]::Zero
    # LOGON32_LOGON_NETWORK (3), default provider.
    if (-not [OstenaLogon]::LogonUser($User, '.', $Password, 3, 0, [ref] $token)) {
        Write-Host "::error::LogonUser failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        exit 2
    }
    $handle = [Microsoft.Win32.SafeHandles.SafeAccessTokenHandle]::new($token)
    $result = [Security.Principal.WindowsIdentity]::RunImpersonated($handle, [Func[string]] {
        try {
            $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'ostena-agent', [IO.Pipes.PipeDirection]::InOut)
            $pipe.Connect(3000)
            $pipe.Dispose()
            'connected'
        } catch [UnauthorizedAccessException] {
            'denied'
        } catch {
            "other: $($_.Exception.GetType().Name) $($_.Exception.Message)"
        }
    })
    $handle.Dispose()
} finally {
    try { $computer.Delete('User', $User) } catch { }
}

Write-Host "non-administrator access to the control pipe: $result"
switch ($result) {
    'denied' { exit 0 }
    'connected' { exit 1 }
    default { exit 2 }
}
