[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ReleaseRoot,
    [Parameter(Mandatory = $true)][ValidatePattern("^\d+\.\d+\.\d+$")][string]$Version,
    [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-fA-F]{40}$")][string]$ExpectedCommit,
    [string]$PythonPath = "python",
    [string]$Repository = $env:GITHUB_REPOSITORY,
    [string]$TemporaryRoot = $env:RUNNER_TEMP
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Repository)) {
    throw "GitHub repository is required."
}
if ([string]::IsNullOrWhiteSpace($TemporaryRoot)) {
    throw "A temporary directory is required."
}

$productName = "ArubaSessionTracker"
$tag = "continuous"
$zipName = "$productName`_v$Version`_windows_x64.zip"
$zip = Join-Path $ReleaseRoot $zipName
$sha = "$zip.sha256"
$sbom = Join-Path $ReleaseRoot "$productName`_v$Version`_sbom.cdx.json"
$notes = Join-Path $ReleaseRoot "release-notes-v$Version.md"
$zipDigest = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
$zipSize = [int64](Get-Item -LiteralPath $zip).Length
$ownerMarker = "<!-- aruba-session-tracker-continuous:$($ExpectedCommit.ToLowerInvariant()) -->"
$canonicalAssetPattern = (
    '^ArubaSessionTracker_v\d+\.\d+\.\d+_' +
    '(windows_x64\.zip(\.sha256)?|sbom\.cdx\.json)$'
)
$temporaryAssetPattern = (
    '^(previous-\d+|candidate-[0-9a-fA-F]{12})--' +
    'ArubaSessionTracker_v\d+\.\d+\.\d+_' +
    '(windows_x64\.zip(\.sha256)?|sbom\.cdx\.json)$'
)

function Invoke-GhChecked {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $null = & gh @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "GitHub CLI command failed: gh $($Arguments -join ' ')"
    }
}

function Invoke-GhJson {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$AllowNotFound
    )
    $errorPath = Join-Path $TemporaryRoot "gh-error-$([Guid]::NewGuid()).txt"
    $output = & gh @Arguments 2> $errorPath
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
        return (($output -join "`n") | ConvertFrom-Json)
    }
    $errorText = if (Test-Path -LiteralPath $errorPath) {
        Get-Content -LiteralPath $errorPath -Raw
    }
    else {
        ""
    }
    if ($AllowNotFound -and $errorText -match '(?i)HTTP 404') {
        return $null
    }
    throw "GitHub API command failed: gh $($Arguments -join ' ')"
}

function Get-ContinuousRelease {
    # The tag endpoint intentionally does not return drafts. Discover by release
    # id so an interrupted draft remains addressable and cannot cause duplicate
    # drafts or tag-ambiguous uploads on the next run.
    $all = @()
    foreach ($page in 1..100) {
        $batch = @(
            Invoke-GhJson @(
                "api", "repos/$Repository/releases?per_page=100&page=$page"
            )
        )
        $all += $batch
        if ($batch.Count -lt 100) {
            break
        }
        if ($page -eq 100) {
            throw "Release discovery reached its safe pagination bound."
        }
    }
    $matches = @($all | Where-Object { [string]$_.tag_name -ceq $tag })
    if ($matches.Count -eq 0) {
        return $null
    }
    $candidatesPath = Join-Path $TemporaryRoot "continuous-candidates.json"
    $matches | ConvertTo-Json -Depth 20 -AsArray |
        Set-Content -LiteralPath $candidatesPath -Encoding utf8
    $selectionOutput = @(
        & $PythonPath tools/continuous_release_state.py select-release `
            --releases-json $candidatesPath
    )
    if ($LASTEXITCODE -ne 0 -or $selectionOutput.Count -ne 1) {
        throw "Could not safely select the canonical continuous release."
    }
    $selection = ([string]$selectionOutput[0]) | ConvertFrom-Json
    $keeper = @($matches | Where-Object { $_.id -eq $selection.keeper_id })
    if ($keeper.Count -ne 1) {
        throw "The selected continuous release id is unavailable."
    }
    foreach ($assetId in @($selection.cleanup_asset_ids)) {
        Invoke-GhChecked @(
            "api", "-X", "DELETE", "repos/$Repository/releases/assets/$assetId"
        )
    }
    foreach ($duplicateId in @($selection.cleanup_ids)) {
        Invoke-GhChecked @(
            "api", "-X", "DELETE", "repos/$Repository/releases/$duplicateId"
        )
    }
    return Invoke-GhJson @("api", "repos/$Repository/releases/$($keeper[0].id)")
}

function Get-ContinuousTag {
    return Invoke-GhJson @(
        "api", "repos/$Repository/git/ref/tags/$tag"
    ) -AllowNotFound
}

function Get-DirectTagCommit {
    param($TagReference)
    if ($null -eq $TagReference) {
        return $null
    }
    if ($TagReference.object.type -ne "commit") {
        throw "The continuous tag is not a direct commit reference."
    }
    return [string]$TagReference.object.sha
}

function Set-ReleaseDraftState {
    param(
        [Parameter(Mandatory = $true)][int64]$ReleaseId,
        [Parameter(Mandatory = $true)][bool]$Draft
    )
    $payloadPath = Join-Path $TemporaryRoot "continuous-draft-$ReleaseId.json"
    @{ draft = $Draft } | ConvertTo-Json -Compress |
        Set-Content -LiteralPath $payloadPath -Encoding utf8
    return Invoke-GhJson @(
        "api", "-X", "PATCH", "repos/$Repository/releases/$ReleaseId",
        "--input", $payloadPath
    )
}

function Set-ReleaseMetadata {
    param(
        [Parameter(Mandatory = $true)][int64]$ReleaseId,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][bool]$Draft,
        [Parameter(Mandatory = $true)][bool]$Prerelease,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$BodyPath
    )
    $payloadPath = Join-Path $TemporaryRoot "continuous-edit-$ReleaseId.json"
    @{
        tag_name = $tag
        target_commitish = $Target
        name = $Title
        body = Get-Content -LiteralPath $BodyPath -Raw
        draft = $Draft
        prerelease = $Prerelease
        make_latest = "false"
    } | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $payloadPath -Encoding utf8
    return Invoke-GhJson @(
        "api", "-X", "PATCH", "repos/$Repository/releases/$ReleaseId",
        "--input", $payloadPath
    )
}

function Add-ReleaseAsset {
    param(
        [Parameter(Mandatory = $true)][int64]$ReleaseId,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $name = [Uri]::EscapeDataString([IO.Path]::GetFileName($Path))
    return Invoke-GhJson @(
        "api", "-X", "POST",
        "-H", "Content-Type: application/octet-stream",
        "--input", $Path,
        "https://uploads.github.com/repos/$Repository/releases/$ReleaseId/assets?name=$name"
    )
}

function Save-ReleaseAsset {
    param(
        [Parameter(Mandatory = $true)]$Asset,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    if ([string]::IsNullOrWhiteSpace($env:GH_TOKEN)) {
        throw "GH_TOKEN is required to download a draft release asset."
    }
    Invoke-WebRequest `
        -Uri ([string]$Asset.url) `
        -Headers @{
            Accept = "application/octet-stream"
            Authorization = "Bearer $($env:GH_TOKEN)"
            "X-GitHub-Api-Version" = "2022-11-28"
        } `
        -OutFile $Destination
}

function Assert-MainStillExpected {
    $main = Invoke-GhJson @("api", "repos/$Repository/git/ref/heads/main")
    if (
        $main.object.type -ne "commit" -or
        -not [string]::Equals(
            [string]$main.object.sha,
            $ExpectedCommit,
            [StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "A newer main commit exists; this continuous build will not publish."
    }
}

function Assert-ContinuousTagAt {
    param([Parameter(Mandatory = $true)][string]$Commit)
    $tagReference = Get-ContinuousTag
    $actual = Get-DirectTagCommit $tagReference
    if (
        $null -eq $actual -or
        -not [string]::Equals($actual, $Commit, [StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "The continuous tag does not resolve to the expected commit."
    }
}

function Assert-OwnedAssetNames {
    param([object[]]$Assets)
    foreach ($asset in @($Assets)) {
        if (
            $asset.name -notmatch $canonicalAssetPattern -and
            $asset.name -notmatch $temporaryAssetPattern
        ) {
            throw "The workflow-owned continuous release has an unexpected asset."
        }
    }
}

function Write-StageBody {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("staging", "assets_verified", "ready")]
        [string]$Stage
    )
    $destination = Join-Path $TemporaryRoot "continuous-$Stage.md"
    & $PythonPath tools/continuous_release_state.py body `
        --notes $notes `
        --output $destination `
        --stage $Stage `
        --commit $ExpectedCommit `
        --zip-name $zipName `
        --sha256 $zipDigest `
        --size $zipSize
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the durable $Stage release body."
    }
    return $destination
}

function Get-ReconcileAction {
    param(
        $Release,
        $TagReference,
        [switch]$LegacyValidated,
        [switch]$Authenticated,
        [switch]$PublicVerified
    )
    $arguments = @(
        "tools/continuous_release_state.py", "action",
        "--commit", $ExpectedCommit,
        "--zip-name", $zipName,
        "--sha256", $zipDigest,
        "--size", "$zipSize"
    )
    if ($null -ne $Release) {
        $releasePath = Join-Path $TemporaryRoot "continuous-current.json"
        $Release | ConvertTo-Json -Depth 20 |
            Set-Content -LiteralPath $releasePath -Encoding utf8
        $arguments += @("--release-json", $releasePath)
    }
    $tagCommit = Get-DirectTagCommit $TagReference
    if ($null -ne $tagCommit) {
        $arguments += @("--tag-commit", $tagCommit)
    }
    if ($LegacyValidated) { $arguments += "--legacy-validated" }
    if ($Authenticated) { $arguments += "--authenticated" }
    if ($PublicVerified) { $arguments += "--public-verified" }
    $output = @(& $PythonPath @arguments)
    if ($LASTEXITCODE -ne 0 -or $output.Count -ne 1) {
        throw "Could not determine the next continuous reconciliation action."
    }
    return ([string]$output[0]).Trim()
}

function Assert-RemoteContract {
    param(
        [Parameter(Mandatory = $true)]$Release,
        [Parameter(Mandatory = $true)][ValidateSet("draft", "published")][string]$State
    )
    $releasePath = Join-Path $TemporaryRoot "continuous-contract-$State.json"
    $Release | ConvertTo-Json -Depth 20 |
        Set-Content -LiteralPath $releasePath -Encoding utf8
    & $PythonPath tools/check_remote_release.py `
        --release-json $releasePath `
        --tag $tag `
        --expected-commit $ExpectedCommit `
        --state $State `
        --required-marker $ownerMarker `
        --asset "$zipName=$zip"
    if ($LASTEXITCODE -ne 0) {
        throw "The $State continuous release contract failed."
    }
}

function Assert-DownloadedZip {
    param(
        [Parameter(Mandatory = $true)]$Release,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$FailureMessage,
        [switch]$Public
    )
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    $downloaded = Join-Path $Destination $zipName
    $remote = @($Release.assets | Where-Object { $_.name -ceq $zipName })
    if ($remote.Count -ne 1) {
        throw "The continuous release does not contain exactly one expected ZIP."
    }
    if ($Public) {
        Invoke-WebRequest `
            -Uri ([string]$remote[0].browser_download_url) `
            -OutFile $downloaded
    }
    else {
        Save-ReleaseAsset $remote[0] $downloaded
    }
    if (
        -not (Test-Path -LiteralPath $downloaded -PathType Leaf) -or
        (Get-FileHash -LiteralPath $downloaded -Algorithm SHA256).Hash -ne
            (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    ) {
        throw $FailureMessage
    }
}

./tools/verify_publish_assets.ps1 `
    -ReleaseRoot $ReleaseRoot `
    -Version $Version `
    -ExpectedCommit $ExpectedCommit `
    -PythonPath $PythonPath

$stageBodies = @{
    staging = Write-StageBody "staging"
    assets_verified = Write-StageBody "assets_verified"
    ready = Write-StageBody "ready"
}
$legacyValidated = $false
$authenticated = $false
$publicVerified = $false
$transactionStarted = $false
$completed = $false
$tagReference = Get-ContinuousTag
Assert-MainStillExpected
$release = Get-ContinuousRelease

try {
    foreach ($attempt in 1..40) {
        $action = Get-ReconcileAction `
            -Release $release `
            -TagReference $tagReference `
            -LegacyValidated:$legacyValidated `
            -Authenticated:$authenticated `
            -PublicVerified:$publicVerified
        switch ($action) {
            "create_draft" {
                Assert-MainStillExpected
                $transactionStarted = $true
                $payloadPath = Join-Path $TemporaryRoot "continuous-create.json"
                @{
                    tag_name = $tag
                    target_commitish = $ExpectedCommit
                    name = "Aruba Session Tracker continuous"
                    body = Get-Content -LiteralPath $stageBodies.staging -Raw
                    draft = $true
                    prerelease = $true
                    make_latest = "false"
                } | ConvertTo-Json -Depth 5 |
                    Set-Content -LiteralPath $payloadPath -Encoding utf8
                $release = Invoke-GhJson @(
                    "api", "-X", "POST", "repos/$Repository/releases",
                    "--input", $payloadPath
                )
                $tagReference = Get-ContinuousTag
            }
            "validate_legacy" {
                $legacyRoot = Join-Path $TemporaryRoot "continuous-legacy-validation"
                New-Item -ItemType Directory -Force -Path $legacyRoot | Out-Null
                $legacyZip = @(
                    $release.assets | Where-Object {
                        $_.name -match '^ArubaSessionTracker_v\d+\.\d+\.\d+_windows_x64\.zip$'
                    }
                )[0]
                $legacySha = @(
                    $release.assets | Where-Object { $_.name -eq "$($legacyZip.name).sha256" }
                )[0]
                $legacySbom = @(
                    $release.assets | Where-Object {
                        $_.name -match '^ArubaSessionTracker_v\d+\.\d+\.\d+_sbom\.cdx\.json$'
                    }
                )[0]
                foreach ($asset in @($legacyZip, $legacySha, $legacySbom)) {
                    Save-ReleaseAsset `
                        $asset `
                        (Join-Path $legacyRoot ([string]$asset.name))
                }
                & $PythonPath tools/continuous_release_state.py validate-legacy `
                    --zip (Join-Path $legacyRoot $legacyZip.name) `
                    --sha256-file (Join-Path $legacyRoot $legacySha.name) `
                    --sbom (Join-Path $legacyRoot $legacySbom.name)
                if ($LASTEXITCODE -ne 0) {
                    throw "The legacy continuous trio failed semantic validation."
                }
                $legacyValidated = $true
            }
            "hide_and_mark_staging" {
                Assert-MainStillExpected
                $transactionStarted = $true
                $release = Set-ReleaseMetadata `
                    ([int64]$release.id) `
                    $ExpectedCommit `
                    $true `
                    $true `
                    "Aruba Session Tracker continuous" `
                    $stageBodies.staging
                $authenticated = $false
                $tagReference = Get-ContinuousTag
            }
            "mark_staging" {
                $transactionStarted = $true
                $release = Set-ReleaseMetadata `
                    ([int64]$release.id) `
                    $ExpectedCommit `
                    $true `
                    $true `
                    "Aruba Session Tracker continuous" `
                    $stageBodies.staging
                $authenticated = $false
                $tagReference = Get-ContinuousTag
            }
            "replace_assets" {
                if ($release.draft -ne $true) {
                    throw "Continuous assets may be replaced only while the release is a draft."
                }
                Assert-OwnedAssetNames @($release.assets)
                $transactionStarted = $true
                foreach ($asset in @($release.assets)) {
                    Invoke-GhChecked @(
                        "api", "-X", "DELETE",
                        "repos/$Repository/releases/assets/$($asset.id)"
                    )
                }
                $null = Add-ReleaseAsset ([int64]$release.id) $zip
                $authenticated = $false
                $release = Invoke-GhJson @(
                    "api", "repos/$Repository/releases/$($release.id)"
                )
                $tagReference = Get-ContinuousTag
            }
            "verify_draft_download" {
                Assert-RemoteContract $release "draft"
                Assert-DownloadedZip `
                    $release `
                    (Join-Path $TemporaryRoot "continuous-draft-download") `
                    "The authenticated continuous ZIP differs from the verified input."
                $authenticated = $true
            }
            "mark_assets_verified" {
                $release = Set-ReleaseMetadata `
                    ([int64]$release.id) `
                    $ExpectedCommit `
                    $true `
                    $true `
                    "Aruba Session Tracker continuous" `
                    $stageBodies.assets_verified
                $tagReference = Get-ContinuousTag
            }
            "align_tag" {
                Assert-MainStillExpected
                $transactionStarted = $true
                if ($null -eq $tagReference) {
                    Invoke-GhChecked @(
                        "api", "-X", "POST", "repos/$Repository/git/refs",
                        "-f", "ref=refs/tags/$tag", "-f", "sha=$ExpectedCommit"
                    )
                }
                else {
                    Invoke-GhChecked @(
                        "api", "-X", "PATCH", "repos/$Repository/git/refs/tags/$tag",
                        "-f", "sha=$ExpectedCommit", "-F", "force=true"
                    )
                }
                Assert-ContinuousTagAt $ExpectedCommit
                $tagReference = Get-ContinuousTag
            }
            "mark_ready" {
                Assert-RemoteContract $release "draft"
                $release = Set-ReleaseMetadata `
                    ([int64]$release.id) `
                    $ExpectedCommit `
                    $true `
                    $true `
                    "Aruba Session Tracker continuous" `
                    $stageBodies.ready
                $tagReference = Get-ContinuousTag
            }
            "publish" {
                Assert-RemoteContract $release "draft"
                Assert-ContinuousTagAt $ExpectedCommit
                Assert-MainStillExpected
                $transactionStarted = $true
                $release = Set-ReleaseMetadata `
                    ([int64]$release.id) `
                    $ExpectedCommit `
                    $false `
                    $true `
                    "Aruba Session Tracker continuous" `
                    $stageBodies.ready
                Assert-ContinuousTagAt $ExpectedCommit
                $tagReference = Get-ContinuousTag
            }
            "verify_public" {
                Assert-ContinuousTagAt $ExpectedCommit
                $publishedByTag = Invoke-GhJson @(
                    "api", "repos/$Repository/releases/tags/$tag"
                )
                if ([int64]$publishedByTag.id -ne [int64]$release.id) {
                    throw "The public tag endpoint returned a different release id."
                }
                $release = $publishedByTag
                Assert-RemoteContract $release "published"
                Assert-DownloadedZip `
                    $release `
                    (Join-Path $TemporaryRoot "continuous-public-download") `
                    "The public continuous ZIP differs from the verified input." `
                    -Public
                Assert-ContinuousTagAt $ExpectedCommit
                $publicVerified = $true
            }
            "done" {
                $completed = $true
                break
            }
            default {
                throw "Unknown continuous reconciliation action: $action"
            }
        }
        if ($completed) {
            break
        }
    }
    if (-not $completed) {
        throw "Continuous reconciliation did not converge within its action bound."
    }
}
catch {
    $primaryError = $_
    if ($transactionStarted) {
        # GitHub's built-in token cannot republish an older target when workflow
        # files differ from current main. Retain the owned release as a hidden,
        # durable forward state so the next run can resume by release id.
        if ($null -ne $release -and [int64]$release.id -gt 0) {
            try {
                $null = Set-ReleaseDraftState ([int64]$release.id) $true 2>$null
            }
            catch {
                Write-Warning "Could not confirm the interrupted release is hidden."
            }
        }
    }
    throw $primaryError
}

Write-Host "Continuous release converged to one verified Windows x64 ZIP."
