[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ReleaseRoot,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$ExpectedCommit,
    [string]$PythonPath = "python"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$productName = "ArubaSessionTracker"
$zipName = "$productName`_v$Version`_windows_x64.zip"
$shaName = "$zipName.sha256"
$sbomName = "$productName`_v$Version`_sbom.cdx.json"
$notesName = "release-notes-v$Version.md"
$expectedNames = @($zipName, $shaName, $sbomName, $notesName) | Sort-Object
$files = @(Get-ChildItem -LiteralPath $ReleaseRoot -File)
$actualNames = @($files.Name | Sort-Object)
$differences = @(Compare-Object -ReferenceObject $expectedNames -DifferenceObject $actualNames)
if ($files.Count -ne 4 -or $differences.Count -ne 0) {
    throw "Downloaded artifact does not contain the exact four publish inputs."
}

$zip = Join-Path $ReleaseRoot $zipName
$sha = Join-Path $ReleaseRoot $shaName
$sbom = Join-Path $ReleaseRoot $sbomName
$sidecarText = Get-Content -LiteralPath $sha -Raw
$sidecarPattern = (
    '\A(?<hash>[0-9A-Fa-f]{64})  ' +
    [regex]::Escape($zipName) +
    '\r?\n?\z'
)
$sidecarMatch = [regex]::Match($sidecarText, $sidecarPattern)
$actualHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
if (
    -not $sidecarMatch.Success -or
    -not [string]::Equals(
        $sidecarMatch.Groups['hash'].Value,
        $actualHash,
        [StringComparison]::OrdinalIgnoreCase
    )
) {
    throw "Release ZIP does not match its SHA-256 sidecar."
}

$sbomDocument = Get-Content -LiteralPath $sbom -Raw | ConvertFrom-Json
if ($sbomDocument.bomFormat -ne "CycloneDX") {
    throw "Release SBOM is not CycloneDX."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
try {
    $buildInfoEntries = @(
        $archive.Entries | Where-Object { $_.FullName -match '(^|[\\/])BUILD_INFO\.json$' }
    )
    if ($buildInfoEntries.Count -ne 1) {
        throw "Release ZIP must contain exactly one BUILD_INFO.json."
    }
    $reader = [System.IO.StreamReader]::new($buildInfoEntries[0].Open())
    try {
        $buildInfo = $reader.ReadToEnd() | ConvertFrom-Json
    }
    finally {
        $reader.Dispose()
    }
}
finally {
    $archive.Dispose()
}

if (
    $buildInfo.product -ne $productName -or
    $buildInfo.version -ne $Version -or
    $buildInfo.architecture -ne "windows-x64" -or
    $buildInfo.dirtyTree -ne $false -or
    -not [string]::Equals(
        $buildInfo.commit,
        $ExpectedCommit,
        [StringComparison]::OrdinalIgnoreCase
    )
) {
    throw "Release ZIP provenance does not match the verified build."
}

& $PythonPath tools/verify_release.py `
    --zip $zip `
    --sha256 $sha `
    --sbom $sbom `
    --runtime-lock requirements-runtime.lock `
    --build-lock requirements-build.lock `
    --pyproject pyproject.toml `
    --component-manifest third_party_components.toml `
    --version $Version `
    --expected-commit $ExpectedCommit
if ($LASTEXITCODE -ne 0) {
    throw "Release package content verification failed."
}
Write-Host "Publish input verification passed for $zipName"
