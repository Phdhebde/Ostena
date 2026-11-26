# Prints what the Windows CI target logged about its RDP sessions and the
# logons of the test account, to tell why a session ended (run by the CI
# after a failure of crates/ostena-rdp/tests/windows_target.rs).
#
#   pwsh tests/rdp/windows-target-events.ps1
$ErrorActionPreference = 'Continue'
$Since = (Get-Date).AddMinutes(-30)

function Show([string] $Log, [int[]] $Ids, [string] $Match) {
    Write-Host "=== $Log"
    $Filter = @{ LogName = $Log; StartTime = $Since }
    if ($Ids) { $Filter.Id = $Ids }
    Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue |
        Where-Object { -not $Match -or $_.Message -match $Match } |
        Sort-Object TimeCreated |
        ForEach-Object {
            $Message = ($_.Message -split "`r?`n" | Where-Object { $_.Trim() }) -join ' | '
            Write-Host ("{0:HH:mm:ss.fff} [{1}] {2}" -f $_.TimeCreated, $_.Id, $Message)
        }
}

Show 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
Show 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
Show 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'
Show 'Microsoft-Windows-User Profile Service/Operational'
# Logon, failed logon, logoff, reconnection and disconnection.
Show 'Security' @(4624, 4625, 4634, 4647, 4778, 4779) 'ostena-rdp'
Show 'Application' @(1500, 1502, 1508, 1511, 1515, 1530, 1533, 4005)
Show 'System' @(1, 6005, 6006, 7011, 7031, 7034, 7036, 7045)
Write-Host '=== sessions'
query session
# A diagnosis, never a verdict: the step that failed is the test.
exit 0
