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
    return Invoke-GhJson @(
        "api", "repos/$Repository/releases/tags/$tag"
    ) -AllowNotFound
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
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Invoke-GhChecked @(
        "release", "download", $tag,
        "--repo", $Repository,
        "--dir", $Destination,
        "--clobber",
        "--pattern", $zipName
    )
    $downloaded = Join-Path $Destination $zipName
    if (
        -not (Test-Path -LiteralPath $downloaded -PathType Leaf) -or
        (Get-FileHash -LiteralPath $downloaded -Algorithm SHA256).Hash -ne
            (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    ) {
        throw $FailureMessage
    }
}

function Save-RollbackState {
    param(
        [Parameter(Mandatory = $true)]$Release,
        [Parameter(Mandatory = $true)]$TagReference
    )
    if ($Release.draft -ne $false -or $Release.prerelease -ne $true) {
        throw "Only a published continuous prerelease can be retained for rollback."
    }
    if (
        [string]$Release.tag_name -cne $tag -or
        $null -eq $Release.name -or
        [string]::IsNullOrWhiteSpace([string]$Release.name) -or
        $null -eq $Release.body -or
        [string]::IsNullOrWhiteSpace([string]$Release.target_commitish)
    ) {
        throw "The prior continuous metadata cannot be restored exactly."
    }
    $oldCommit = Get-DirectTagCommit $TagReference
    if ($null -eq $oldCommit) {
        throw "The prior continuous commit is unavailable."
    }
    Assert-OwnedAssetNames @($Release.assets)
    $root = Join-Path $TemporaryRoot "continuous-rollback"
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $bodyPath = Join-Path $root "prior-body.md"
    [IO.File]::WriteAllText(
        $bodyPath,
        [string]$Release.body,
        [Text.UTF8Encoding]::new($false)
    )
    $assets = @()
    foreach ($asset in @($Release.assets)) {
        Invoke-GhChecked @(
            "release", "download", $tag,
            "--repo", $Repository,
            "--dir", $root,
            "--clobber",
            "--pattern", ([string]$asset.name)
        )
        $path = Join-Path $root ([string]$asset.name)
        $digest = "sha256:$((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant())"
        if (
            [int64]$asset.size -ne [int64](Get-Item -LiteralPath $path).Length -or
            -not [string]::Equals(
                [string]$asset.digest,
                $digest,
                [StringComparison]::OrdinalIgnoreCase
            )
        ) {
            throw "A prior continuous asset could not be retained exactly."
        }
        $assets += [pscustomobject]@{
            Name = [string]$asset.name
            Path = $path
            Size = [int64]$asset.size
            Digest = $digest
        }
    }
    return [pscustomobject]@{
        ReleaseId = [int64]$Release.id
        TagName = [string]$Release.tag_name
        Commit = $oldCommit
        Title = [string]$Release.name
        Body = [string]$Release.body
        BodyPath = $bodyPath
        Target = [string]$Release.target_commitish
        Draft = [bool]$Release.draft
        Prerelease = [bool]$Release.prerelease
        Assets = @($assets)
    }
}

function Restore-RollbackState {
    param([Parameter(Mandatory = $true)]$Rollback)
    Invoke-GhChecked @("release", "edit", $tag, "--repo", $Repository, "--draft")
    $current = Invoke-GhJson @(
        "api", "repos/$Repository/releases/$($Rollback.ReleaseId)"
    )
    Assert-OwnedAssetNames @($current.assets)
    foreach ($asset in @($current.assets)) {
        Invoke-GhChecked @(
            "api", "-X", "DELETE",
            "repos/$Repository/releases/assets/$($asset.id)"
        )
    }
    $paths = @($Rollback.Assets | ForEach-Object { $_.Path })
    $arguments = @("release", "upload", $tag) + $paths + @("--repo", $Repository)
    Invoke-GhChecked $arguments

    $tagReference = Get-ContinuousTag
    if ($null -eq $tagReference) {
        Invoke-GhChecked @(
            "api", "-X", "POST", "repos/$Repository/git/refs",
            "-f", "ref=refs/tags/$tag", "-f", "sha=$($Rollback.Commit)"
        )
    }
    else {
        Invoke-GhChecked @(
            "api", "-X", "PATCH", "repos/$Repository/git/refs/tags/$tag",
            "-f", "sha=$($Rollback.Commit)", "-F", "force=true"
        )
    }
    Assert-ContinuousTagAt $Rollback.Commit
    Invoke-GhChecked @(
        "release", "edit", $tag,
        "--repo", $Repository,
        "--target", $Rollback.Target,
        "--draft=false",
        "--prerelease",
        "--title", $Rollback.Title,
        "--notes-file", $Rollback.BodyPath
    )
    Assert-ContinuousTagAt $Rollback.Commit
    $restored = Get-ContinuousRelease
    if (
        $null -eq $restored -or
        [int64]$restored.id -ne [int64]$Rollback.ReleaseId -or
        $restored.draft -ne $Rollback.Draft -or
        $restored.prerelease -ne $Rollback.Prerelease -or
        [string]$restored.tag_name -cne [string]$Rollback.TagName -or
        [string]$restored.name -cne [string]$Rollback.Title -or
        [string]$restored.body -cne [string]$Rollback.Body -or
        [string]$restored.target_commitish -cne [string]$Rollback.Target
    ) {
        throw "The restored release metadata differs from the exact prior state."
    }
    $restoredNames = @($restored.assets.name | Sort-Object)
    $expectedNames = @($Rollback.Assets.Name | Sort-Object)
    if (Compare-Object $restoredNames $expectedNames) {
        throw "The restored release asset names differ from the exact prior state."
    }
    foreach ($expected in @($Rollback.Assets)) {
        $remote = @($restored.assets | Where-Object { $_.name -eq $expected.Name })
        if (
            $remote.Count -ne 1 -or
            [int64]$remote[0].size -ne [int64]$expected.Size -or
            -not [string]::Equals(
                [string]$remote[0].digest,
                [string]$expected.Digest,
                [StringComparison]::OrdinalIgnoreCase
            )
        ) {
            throw "A restored release asset differs from its exact prior metadata."
        }
        $publicPath = Join-Path $TemporaryRoot "restored-$($expected.Name)"
        Invoke-WebRequest -Uri $remote[0].browser_download_url -OutFile $publicPath
        if (
            (Get-FileHash -LiteralPath $publicPath -Algorithm SHA256).Hash -ne
            (Get-FileHash -LiteralPath $expected.Path -Algorithm SHA256).Hash
        ) {
            throw "A restored public asset differs from its exact prior bytes."
        }
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
$rollback = $null
$release = Get-ContinuousRelease
$tagReference = Get-ContinuousTag
Assert-MainStillExpected

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
                    Invoke-GhChecked @(
                        "release", "download", $tag,
                        "--repo", $Repository,
                        "--dir", $legacyRoot,
                        "--clobber",
                        "--pattern", ([string]$asset.name)
                    )
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
                if ($null -eq $rollback) {
                    $rollback = Save-RollbackState $release $tagReference
                }
                $transactionStarted = $true
                Invoke-GhChecked @(
                    "release", "edit", $tag,
                    "--repo", $Repository,
                    "--target", $ExpectedCommit,
                    "--draft",
                    "--prerelease",
                    "--title", "Aruba Session Tracker continuous",
                    "--notes-file", $stageBodies.staging
                )
                $authenticated = $false
                $release = Get-ContinuousRelease
                $tagReference = Get-ContinuousTag
            }
            "mark_staging" {
                $transactionStarted = $true
                Invoke-GhChecked @(
                    "release", "edit", $tag,
                    "--repo", $Repository,
                    "--target", $ExpectedCommit,
                    "--draft",
                    "--prerelease",
                    "--title", "Aruba Session Tracker continuous",
                    "--notes-file", $stageBodies.staging
                )
                $authenticated = $false
                $release = Get-ContinuousRelease
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
                Invoke-GhChecked @(
                    "release", "upload", $tag, $zip, "--repo", $Repository
                )
                $authenticated = $false
                $release = Get-ContinuousRelease
                $tagReference = Get-ContinuousTag
            }
            "verify_draft_download" {
                Assert-RemoteContract $release "draft"
                Assert-DownloadedZip `
                    (Join-Path $TemporaryRoot "continuous-draft-download") `
                    "The authenticated continuous ZIP differs from the verified input."
                $authenticated = $true
            }
            "mark_assets_verified" {
                Invoke-GhChecked @(
                    "release", "edit", $tag,
                    "--repo", $Repository,
                    "--target", $ExpectedCommit,
                    "--draft",
                    "--prerelease",
                    "--title", "Aruba Session Tracker continuous",
                    "--notes-file", $stageBodies.assets_verified
                )
                $release = Get-ContinuousRelease
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
                Invoke-GhChecked @(
                    "release", "edit", $tag,
                    "--repo", $Repository,
                    "--target", $ExpectedCommit,
                    "--draft",
                    "--prerelease",
                    "--title", "Aruba Session Tracker continuous",
                    "--notes-file", $stageBodies.ready
                )
                $release = Get-ContinuousRelease
                $tagReference = Get-ContinuousTag
            }
            "publish" {
                Assert-RemoteContract $release "draft"
                Assert-ContinuousTagAt $ExpectedCommit
                Assert-MainStillExpected
                $transactionStarted = $true
                Invoke-GhChecked @(
                    "release", "edit", $tag,
                    "--repo", $Repository,
                    "--target", $ExpectedCommit,
                    "--draft=false",
                    "--prerelease",
                    "--title", "Aruba Session Tracker continuous",
                    "--notes-file", $stageBodies.ready
                )
                Assert-ContinuousTagAt $ExpectedCommit
                $release = Get-ContinuousRelease
                $tagReference = Get-ContinuousTag
            }
            "verify_public" {
                Assert-ContinuousTagAt $ExpectedCommit
                Assert-RemoteContract $release "published"
                Assert-DownloadedZip `
                    (Join-Path $TemporaryRoot "continuous-public-download") `
                    "The public continuous ZIP differs from the verified input."
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
    if ($transactionStarted -and $null -ne $rollback) {
        try {
            Restore-RollbackState $rollback
        }
        catch {
            $rollbackError = $_
            $null = & gh release edit $tag --repo $Repository --draft 2>$null
            throw (
                "Continuous update failed and exact rollback also failed: " +
                "$($primaryError.Exception.Message); $($rollbackError.Exception.Message)"
            )
        }
    }
    elseif ($transactionStarted) {
        # The durable body marker remains the source of truth for the next run.
        # Hiding is best effort because the publish response may be ambiguous.
        $null = & gh release edit $tag --repo $Repository --draft 2>$null
    }
    throw $primaryError
}

Write-Host "Continuous release converged to one verified Windows x64 ZIP."
