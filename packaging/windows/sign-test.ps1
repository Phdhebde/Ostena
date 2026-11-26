# Authenticode signature with a TEST certificate drawn for this CI job only
# (ADR-0024, as ADR-0017 for the manifest): ECDSA P-256 / SHA-256, private
# key non-exportable and deleted at the end of the script, public
# certificate exported for the installation tests. It proves nothing about
# the origin of a file: anyone can draw such a certificate. The publication
# certificate comes with lot L15.
#
#   packaging/windows/sign-test.ps1 -Files a.exe,b.msi -Certificate out.cer -Name exe
param(
    [Parameter(Mandatory)] [string[]] $Files,
    [Parameter(Mandatory)] [string] $Certificate,
    [Parameter(Mandatory)] [string] $Name
)

$ErrorActionPreference = 'Stop'

# signtool of the Windows SDK of the runner (no download).
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { Write-Host '::error::signtool.exe not found (Windows SDK)'; exit 1 }

$cert = New-SelfSignedCertificate -Type CodeSigningCert `
    -Subject "CN=Ostena CI test signature ($Name), O=not trusted" `
    -KeyAlgorithm ECDSA_nistP256 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable `
    -NotAfter (Get-Date).AddDays(30) -CertStoreLocation Cert:\CurrentUser\My
try {
    foreach ($file in $Files) {
        # No timestamp: offline, and the certificate is a test one.
        & $signtool.FullName sign /q /fd SHA256 /s My /sha1 $cert.Thumbprint $file
        if ($LASTEXITCODE -ne 0) { Write-Host "::error::signtool sign $file ($LASTEXITCODE)"; exit 1 }
    }
    Export-Certificate -Cert $cert -FilePath $Certificate -Type CERT | Out-Null
} finally {
    Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey
}

# Verification as an installation would do it: the test certificate trusted
# on this throwaway runner only.
Import-Certificate -FilePath $Certificate -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
foreach ($file in $Files) {
    $sig = Get-AuthenticodeSignature $file
    Write-Host "$file : $($sig.Status), $($sig.SignerCertificate.Subject), $($sig.SignerCertificate.PublicKey.Oid.FriendlyName)"
    if ($sig.Status -ne 'Valid') { Write-Host "::error::$file : $($sig.Status) $($sig.StatusMessage)"; exit 1 }
}
# A modified copy is refused.
$copy = Join-Path $env:RUNNER_TEMP ("tampered-" + (Split-Path -Leaf $Files[0]))
Copy-Item $Files[0] $copy -Force
$bytes = [IO.File]::ReadAllBytes($copy)
# A byte in the middle of the file, which the signed hash covers.
$bytes[[int]($bytes.Length / 2)] = $bytes[[int]($bytes.Length / 2)] -bxor 0xFF
[IO.File]::WriteAllBytes($copy, $bytes)
$sig = Get-AuthenticodeSignature $copy
Write-Host "modified copy: $($sig.Status)"
if ($sig.Status -eq 'Valid') { Write-Host '::error::a modified file still has a valid signature'; exit 1 }
Remove-Item $copy
exit 0
