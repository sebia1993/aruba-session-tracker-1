[CmdletBinding()]
param(
    [string]$PythonPath = "python",

    [ValidatePattern("^\d+\.\d+\.\d+$")]
    [string]$Version = "0.5.5",

    [switch]$SkipValidation,
    [switch]$UseCurrentEnvironment,
    [switch]$AllowDirty
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$artifactsRoot = Join-Path $repoRoot "artifacts"
$buildRoot = Join-Path $artifactsRoot "build"
$distRoot = Join-Path $artifactsRoot "dist"
$releaseRoot = Join-Path $artifactsRoot "release"
$productName = "ArubaSessionTracker"
$bundleRoot = Join-Path $distRoot $productName

function Resolve-PhysicalPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    $current = $root
    foreach ($segment in ($fullPath.Substring($root.Length) -split '[\\/]' | Where-Object { $_ })) {
        $candidate = Join-Path $current $segment
        if (Test-Path -LiteralPath $candidate) {
            $item = Get-Item -Force -LiteralPath $candidate
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                $target = [string]@($item.Target)[0]
                if ([string]::IsNullOrEmpty($target)) {
                    throw "Could not resolve reparse point target: $candidate"
                }
                if (-not [IO.Path]::IsPathRooted($target)) {
                    $target = Join-Path (Split-Path -Parent $candidate) $target
                }
                $current = [IO.Path]::GetFullPath($target)
                continue
            }
        }
        $current = $candidate
    }
    return [IO.Path]::GetFullPath($current)
}

function Assert-RepoChild {
    param([Parameter(Mandatory = $true)][string]$Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $repoPrefix = $repoRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing filesystem mutation outside the repository: $fullPath"
    }
    if ($fullPath -eq $repoRoot) {
        throw "Refusing filesystem mutation against the repository root."
    }
    $current = $fullPath
    while (-not $current.Equals($repoRoot, [StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -Force -LiteralPath $current
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing filesystem mutation through a reparse point: $current"
            }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $current) {
            throw "Could not prove mutation stays inside the repository: $fullPath"
        }
        $current = $parent
    }
    return $fullPath
}

function Remove-SafeDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    $fullPath = Assert-RepoChild $Path
    if (Test-Path -LiteralPath $fullPath) {
        Remove-Item -LiteralPath $fullPath -Recurse -Force
    }
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Command $($Arguments -join ' ')"
    }
}

function Get-GitStatusSnapshot {
    $lines = @(& git status --porcelain=v1 --untracked-files=all 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect the complete Git working tree state."
    }
    return [string]::Join("`n", $lines)
}

$packagingInjectionNames = @(
    "CONDA_PREFIX",
    "PYTHONHOME",
    "PYTHONPATH",
    "QML2_IMPORT_PATH",
    "QT_PLUGIN_PATH",
    "QT_QPA_PLATFORM_PLUGIN_PATH",
    "VIRTUAL_ENV"
)
$packagingEnvironmentBefore = @{}
foreach ($environmentName in $packagingInjectionNames) {
    $environmentPath = "Env:$environmentName"
    if (Test-Path -LiteralPath $environmentPath) {
        $packagingEnvironmentBefore[$environmentName] = (Get-Item -LiteralPath $environmentPath).Value
    }
    Remove-Item -LiteralPath $environmentPath -ErrorAction SilentlyContinue
}

Push-Location $repoRoot
try {
    $env:PYTHONUTF8 = "1"
    $env:PYTHONIOENCODING = "utf-8"
    $env:QT_QPA_PLATFORM = "offscreen"

    Invoke-Checked $PythonPath @(
        "-c",
        "import platform,sys; assert sys.version_info[:2] == (3,13), sys.version; assert platform.system() == 'Windows'; assert platform.machine().upper() in {'AMD64','X86_64'}"
    )
    Invoke-Checked $PythonPath @("tools/check_version.py", "--expected", $Version)

    $gitCommit = "unknown"
    $gitDirty = $true
    $gitStateBefore = ""
    $gitStateAvailable = $false
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $gitTopLevelOutput = & git rev-parse --show-toplevel 2>$null
        $gitTopLevel = ([string]$gitTopLevelOutput).Trim()
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrEmpty($gitTopLevel)) {
            $resolvedGitRoot = Resolve-PhysicalPath $gitTopLevel
            $resolvedRepoRoot = Resolve-PhysicalPath $repoRoot
            if (-not $resolvedGitRoot.Equals($resolvedRepoRoot, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Git root does not match the build repository: $resolvedGitRoot"
            }
            $gitCommitOutput = & git rev-parse --verify HEAD 2>$null
            if ($LASTEXITCODE -eq 0) {
                $gitCommit = ([string]$gitCommitOutput).Trim()
            }
            $gitStateBefore = Get-GitStatusSnapshot
            $gitStateAvailable = $true
            $gitDirty = -not [string]::IsNullOrEmpty($gitStateBefore)
        }
    }
    if (($gitCommit -eq "unknown" -or $gitDirty) -and -not $AllowDirty) {
        throw "Refusing a release build without a clean Git commit. Use -AllowDirty only for local testing."
    }

    Remove-SafeDirectory $buildRoot
    Remove-SafeDirectory $distRoot
    Remove-SafeDirectory $releaseRoot
    New-Item -ItemType Directory -Force -Path $buildRoot, $distRoot, $releaseRoot | Out-Null

    $toolPython = $PythonPath
    if (-not $UseCurrentEnvironment) {
        $toolVenvRoot = Join-Path $buildRoot "tooling-venv"
        Invoke-Checked $PythonPath @("-m", "venv", $toolVenvRoot)
        $toolPython = Join-Path $toolVenvRoot "Scripts\python.exe"
        Invoke-Checked $toolPython @(
            "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
            "-r", "requirements-dev.lock"
        )
        Invoke-Checked $toolPython @(
            "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
            "--no-deps", "--no-build-isolation", "--check-build-dependencies", "-e", "."
        )
    }

    if (-not $SkipValidation) {
        & (Join-Path $repoRoot "tools\validate.ps1") -PythonPath $toolPython
    }

    $packageVenvRoot = Join-Path $buildRoot "package-venv"
    Invoke-Checked $PythonPath @("-m", "venv", $packageVenvRoot)
    $packagePython = Join-Path $packageVenvRoot "Scripts\python.exe"
    Invoke-Checked $packagePython @(
        "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
        "-r", "requirements-build.lock"
    )
    Invoke-Checked $packagePython @(
        "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
        "--no-deps", "--no-build-isolation", "--check-build-dependencies", "-e", "."
    )

    # PyInstaller's Qt hook scans PATH for optional native dependencies. Keep
    # build-host tools (Poppler, Git, VPN clients, and similar programs) out of
    # that search so their OpenSSL/ICU DLLs cannot silently enter the bundle.
    $packagingPathBefore = $env:PATH
    $packageScripts = Split-Path -Parent $packagePython
    $packagingPath = @(
        $packageScripts,
        [Environment]::SystemDirectory,
        $env:SystemRoot
    ) | Select-Object -Unique
    try {
        $env:PATH = [string]::Join([IO.Path]::PathSeparator, $packagingPath)
        Invoke-Checked $packagePython @(
            "tools/check_packaging_environment.py",
            "--allowed-path", $packageScripts,
            "--allowed-path", [Environment]::SystemDirectory,
            "--allowed-path", $env:SystemRoot
        )
        Invoke-Checked $packagePython @(
            "-m", "PyInstaller", "--clean", "--noconfirm", "--windowed", "--onedir",
            "--name", $productName,
            "--paths", (Join-Path $repoRoot "src"),
            "--workpath", (Join-Path $buildRoot "pyinstaller"),
            "--distpath", $distRoot,
            "--specpath", $buildRoot,
            (Join-Path $repoRoot "src\aruba_session_tracker\__main__.py")
        )
    }
    finally {
        $env:PATH = $packagingPathBefore
    }

    if ($gitStateAvailable -and (Get-GitStatusSnapshot) -ne $gitStateBefore) {
        throw "The source tree changed while the package was being built."
    }
    $exePath = Join-Path $bundleRoot "$productName.exe"
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        throw "PyInstaller did not produce the expected EXE: $exePath"
    }

    # Qt 6.11 on Windows 11 imports the unversioned ICU API from System32.
    # Build-host tools (for example Poppler) can expose an incompatible,
    # version-suffixed ICU on PATH that PyInstaller mistakenly collects.
    $internalRoot = Join-Path $bundleRoot "_internal"
    $unwantedIcuFiles = @(
        Get-ChildItem -LiteralPath $internalRoot -File | Where-Object {
            $_.Name -eq "icuuc.dll" -or $_.Name -match '^icudt\d+\.dll$'
        }
    )
    foreach ($unwantedIcuFile in $unwantedIcuFiles) {
        $safeIcuPath = Assert-RepoChild $unwantedIcuFile.FullName
        Remove-Item -LiteralPath $safeIcuPath -Force
    }

    # The application does not use Qt's OpenSSL TLS backend. Windows Schannel
    # remains bundled, while qopensslbackend and host-PATH OpenSSL variants are
    # excluded to isolate optional dependency search from the build host.
    # CPython's own un-suffixed OpenSSL DLL pair remains and is inventoried.
    $qtOpenSslBackend = Join-Path $internalRoot "PySide6\plugins\tls\qopensslbackend.dll"
    if (Test-Path -LiteralPath $qtOpenSslBackend -PathType Leaf) {
        Remove-Item -LiteralPath (Assert-RepoChild $qtOpenSslBackend) -Force
    }
    $qtSoftwareOpenGl = Join-Path $internalRoot "PySide6\opengl32sw.dll"
    if (Test-Path -LiteralPath $qtSoftwareOpenGl -PathType Leaf) {
        Remove-Item -LiteralPath (Assert-RepoChild $qtSoftwareOpenGl) -Force
    }
    foreach ($forbiddenOpenSslName in @("libcrypto-3-x64.dll", "libssl-3-x64.dll")) {
        $forbiddenOpenSslPath = Join-Path $internalRoot $forbiddenOpenSslName
        if (Test-Path -LiteralPath $forbiddenOpenSslPath) {
            throw "Build-host OpenSSL contamination detected: $forbiddenOpenSslName"
        }
    }
    foreach ($requiredNativePath in @(
        (Join-Path $internalRoot "libcrypto-3.dll"),
        (Join-Path $internalRoot "libssl-3.dll"),
        (Join-Path $internalRoot "PySide6\plugins\tls\qschannelbackend.dll")
    )) {
        if (-not (Test-Path -LiteralPath $requiredNativePath -PathType Leaf)) {
            throw "Required native runtime file is missing: $requiredNativePath"
        }
    }

    foreach ($document in @(
        "README.md", "LICENSE", "CHANGELOG.md", "SECURITY.md", "THIRD_PARTY_NOTICES.txt",
        "OPEN_SOURCE_SOURCE_OFFER.txt", "requirements-runtime.lock"
    )) {
        Copy-Item -LiteralPath (Join-Path $repoRoot $document) -Destination $bundleRoot
    }
    Invoke-Checked $packagePython @(
        "tools/copy_runtime_licenses.py",
        "--lock", (Join-Path $repoRoot "requirements-runtime.lock"),
        "--destination", (Join-Path $bundleRoot "licenses"),
        "--component-manifest", (Join-Path $repoRoot "third_party_components.toml"),
        "--extra-package", "PyInstaller==6.22.2"
    )
    Copy-Item `
        -LiteralPath (Join-Path $repoRoot "licenses\LGPL-3.0-only.txt") `
        -Destination (Join-Path $bundleRoot "licenses\LGPL-3.0-only.txt")
    $pythonBasePrefix = (& $packagePython -c "import sys; print(sys.base_prefix)").Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($pythonBasePrefix)) {
        throw "Could not resolve the packaged CPython base prefix."
    }
    $cpythonLicenseSource = Join-Path $pythonBasePrefix "LICENSE.txt"
    if (-not (Test-Path -LiteralPath $cpythonLicenseSource -PathType Leaf)) {
        throw "The packaged CPython license file is missing: $cpythonLicenseSource"
    }
    $cpythonLicenseRoot = Join-Path $bundleRoot "licenses\cpython"
    $opensslLicenseRoot = Join-Path $bundleRoot "licenses\openssl"
    New-Item -ItemType Directory -Path $cpythonLicenseRoot, $opensslLicenseRoot | Out-Null
    Copy-Item -LiteralPath $cpythonLicenseSource `
        -Destination (Join-Path $cpythonLicenseRoot "LICENSE.txt")
    Copy-Item -LiteralPath (Join-Path $repoRoot "licenses\Apache-2.0.txt") `
        -Destination (Join-Path $opensslLicenseRoot "LICENSE.txt")
    Copy-Item -LiteralPath (Join-Path $repoRoot "licenses\OpenSSL-NOTICE.txt") `
        -Destination (Join-Path $opensslLicenseRoot "NOTICE.txt")

    $pythonVersion = (& $packagePython -c "import platform; print(platform.python_version())").Trim()
    $opensslVersion = (& $packagePython -c "import ssl; print(ssl.OPENSSL_VERSION.split()[1])").Trim()
    $cryptographyOpenSslVersion = (& $packagePython -c "from cryptography.hazmat.bindings.openssl.binding import Binding; b=Binding(); print(b.ffi.string(b.lib.OpenSSL_version(0)).decode().split()[1])").Trim()
    $libyamlVersion = (& $packagePython -c "import _yaml; print(_yaml.get_version_string())").Trim()
    $sqliteVersion = (& $packagePython -c "import sqlite3; print(sqlite3.sqlite_version)").Trim()
    $pyinstallerVersion = (& $packagePython -c "import PyInstaller; print(PyInstaller.__version__)").Trim()
    $qtVersionRows = @(& $packagePython -c "import importlib.metadata as m; print(m.version('PySide6-Essentials')); print(m.version('shiboken6'))")
    if ($LASTEXITCODE -ne 0 -or $qtVersionRows.Count -ne 2) {
        throw "Could not read installed PySide6/Shiboken versions."
    }
    $qtVersion = ([string]$qtVersionRows[0]).Trim()
    $shibokenVersion = ([string]$qtVersionRows[1]).Trim()
    if (
        $pythonVersion -notmatch '^3\.13\.\d+$' -or
        $opensslVersion -notmatch '^3\.\d+\.\d+$' -or
        $cryptographyOpenSslVersion -notmatch '^\d+\.\d+\.\d+$' -or
        $libyamlVersion -notmatch '^\d+\.\d+\.\d+$' -or
        $sqliteVersion -notmatch '^3\.\d+\.\d+$' -or
        $pyinstallerVersion -ne "6.22.2" -or
        $qtVersion -notmatch '^\d+\.\d+\.\d+$' -or
        $qtVersion -ne $shibokenVersion
    ) {
        throw "Could not bind native component versions to the pinned package environment."
    }

    $buildInfo = [ordered]@{
        product = $productName
        version = $Version
        architecture = "windows-x64"
        commit = $gitCommit
        dirtyTree = $gitDirty
        python = $pythonVersion
        openssl = $opensslVersion
        cryptographyOpenssl = $cryptographyOpenSslVersion
        libyaml = $libyamlVersion
        pyinstaller = $pyinstallerVersion
        qt = $qtVersion
        sqlite = $sqliteVersion
        packagedAtUtc = [DateTime]::UtcNow.ToString("o")
        authenticodeSigned = $false
        liveDeviceValidated = $false
    } | ConvertTo-Json
    [IO.File]::WriteAllText(
        (Join-Path $bundleRoot "BUILD_INFO.json"),
        $buildInfo + "`n",
        [Text.UTF8Encoding]::new($false)
    )

    $sbomName = "$productName`_v$Version`_sbom.cdx.json"
    $sbomPath = Join-Path $releaseRoot $sbomName
    Invoke-Checked $toolPython @(
        "-m", "cyclonedx_py", "requirements", "requirements-runtime.lock",
        "--pyproject", "pyproject.toml", "--mc-type", "application",
        "--output-reproducible", "--sv", "1.6", "--of", "JSON", "-o", $sbomPath
    )
    Invoke-Checked $packagePython @(
        "tools/finalize_sbom.py", "--sbom", $sbomPath,
        "--pyproject", (Join-Path $repoRoot "pyproject.toml"),
        "--runtime-lock", (Join-Path $repoRoot "requirements-runtime.lock"),
        "--component-manifest", (Join-Path $repoRoot "third_party_components.toml"),
        "--bundle-root", $bundleRoot,
        "--resolved-manifest", (Join-Path $bundleRoot "THIRD_PARTY_COMPONENTS.json"),
        "--python-version", $pythonVersion,
        "--openssl-version", $opensslVersion,
        "--cryptography-openssl-version", $cryptographyOpenSslVersion,
        "--libyaml-version", $libyamlVersion,
        "--pyinstaller-version", $pyinstallerVersion,
        "--qt-version", $qtVersion,
        "--sqlite-version", $sqliteVersion
    )
    Copy-Item -LiteralPath $sbomPath -Destination (Join-Path $bundleRoot "sbom.cdx.json")

    $zipName = "$productName`_v$Version`_windows_x64.zip"
    $zipPath = Join-Path $releaseRoot $zipName
    Compress-Archive -LiteralPath $bundleRoot -DestinationPath $zipPath -CompressionLevel Optimal
    $digest = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sidecarPath = "$zipPath.sha256"
    [IO.File]::WriteAllText(
        $sidecarPath,
        "$digest  $zipName`n",
        [Text.UTF8Encoding]::new($false)
    )

    $verifyArguments = @(
        "tools/verify_release.py", "--zip", $zipPath,
        "--sha256", $sidecarPath, "--sbom", $sbomPath,
        "--runtime-lock", (Join-Path $repoRoot "requirements-runtime.lock"),
        "--build-lock", (Join-Path $repoRoot "requirements-build.lock"),
        "--pyproject", (Join-Path $repoRoot "pyproject.toml"),
        "--component-manifest", (Join-Path $repoRoot "third_party_components.toml"),
        "--version", $Version, "--smoke"
    )
    if ($gitCommit -match '^[0-9a-fA-F]{40}$') {
        $verifyArguments += @("--expected-commit", $gitCommit)
    }
    if ($AllowDirty) {
        $verifyArguments += "--allow-dirty"
    }
    Invoke-Checked $toolPython $verifyArguments
    Invoke-Checked $toolPython @(
        "tools/release_notes.py", "--version", $Version,
        "--output", (Join-Path $releaseRoot "release-notes-v$Version.md"),
        "--zip", $zipPath,
        "--sha256", $sidecarPath
    )
    if ($gitStateAvailable -and (Get-GitStatusSnapshot) -ne $gitStateBefore) {
        throw "The source tree changed before release asset completion."
    }

    Write-Host "Windows portable release assets created in $releaseRoot"
    Get-ChildItem -LiteralPath $releaseRoot | Select-Object Name, Length
}
finally {
    foreach ($environmentName in $packagingInjectionNames) {
        $environmentPath = "Env:$environmentName"
        Remove-Item -LiteralPath $environmentPath -ErrorAction SilentlyContinue
        if ($packagingEnvironmentBefore.ContainsKey($environmentName)) {
            Set-Item -LiteralPath $environmentPath `
                -Value $packagingEnvironmentBefore[$environmentName]
        }
    }
    Pop-Location
}
