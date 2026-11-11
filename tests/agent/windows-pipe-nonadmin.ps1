# The agent control pipe must refuse a standard (non-administrator) user.
# Creates a temporary local user, opens the pipe while impersonating it, and
# expects access denied. Runs as Administrator; exit code 0 when refused.

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

net user $User $Password /add /expires:never | Out-Null
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
    net user $User /delete | Out-Null
}

Write-Host "non-administrator access to the control pipe: $result"
if ($result -eq 'denied') { exit 0 } else { exit 1 }
