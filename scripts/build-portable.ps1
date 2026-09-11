<#
.SYNOPSIS
    Build the unsigned "portable" fw2sbom package: an official embeddable
    CPython plus fw2sbom's own files, zipped so a customer can extract and
    double-click without installing Python and without meeting SmartScreen.

.DESCRIPTION
    This replaces the hand-run steps in README.md's "免簽章的 Portable 版"
    section. Two things it does that the manual steps cannot:

      * Verifies the downloaded CPython against a pinned SHA-256
        (scripts/python-embed.sha256). A build tool that silently accepts
        whatever bytes the network returns has no business shipping SBOMs.

      * Writes the archive with scripts/make_deterministic_zip.py, so the
        package SHA-256 recorded in RELEASE.md can be re-derived from a clean
        checkout instead of taken on trust.

    Windows-only by nature: python.org publishes the embeddable distribution
    for Windows only. Customers on macOS/Linux run `python3 service.py`.

.PARAMETER PythonVersion
    CPython version to embed. Must have a matching line in the pin file, or
    be pinned with -PinHash on first use.

.PARAMETER EmbedZip
    Use an already-downloaded python-<ver>-embed-<arch>.zip instead of
    fetching one. Still hash-verified.

.PARAMETER PinHash
    Record the downloaded archive's SHA-256 into the pin file. Only use this
    after checking the hash against the release page on python.org -- pinning
    blindly just launders an unverified download into a trusted-looking file.

.EXAMPLE
    .\scripts\build-portable.ps1

.EXAMPLE
    .\scripts\build-portable.ps1 -PythonVersion 3.12.8 -PinHash
#>
[CmdletBinding()]
param(
    [string] $PythonVersion = '3.12.7',
    [ValidateSet('amd64', 'arm64', 'win32')]
    [string] $Architecture = 'amd64',
    [string] $EmbedZip,
    [string] $CacheDir = (Join-Path $env:LOCALAPPDATA 'fw2sbom-build'),
    [switch] $PinHash,
    [switch] $SkipSmokeTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot  = Split-Path -Parent $PSScriptRoot
$DistDir   = Join-Path $RepoRoot 'dist-portable'
$StageDir  = Join-Path $DistDir 'fw2sbom-portable'
$ZipPath   = Join-Path $DistDir 'fw2sbom-portable.zip'
$PinFile   = Join-Path $PSScriptRoot 'python-embed.sha256'
$ZipWriter = Join-Path $PSScriptRoot 'make_deterministic_zip.py'
$BatSource = Join-Path $PSScriptRoot 'Start-fw2sbom.bat'

# fw2sbom's own files, copied in beside python.exe. They must sit at the same
# level as the interpreter: pythonXY._pth puts "." on sys.path, and "." is the
# interpreter's directory, not the working directory.
$PayloadFromRoot = @(
    'service.py',
    'fw2sbom.py',
    'evidence_report.py',
    'spdx_report.py',
    'onecra_logo.png',
    'onecra_icon.png'
)

# The component database. Without it the tool refuses to start, which is the
# correct behaviour but a terrible thing to ship, so the build checks that the
# packs actually arrived.
$PayloadDirs = @('signatures')

$PackageId = "$PythonVersion-$Architecture"
$EmbedName = "python-$PythonVersion-embed-$Architecture.zip"
$EmbedUrl  = "https://www.python.org/ftp/python/$PythonVersion/$EmbedName"

function Write-Step([string] $Message) {
    Write-Host "[build] $Message" -ForegroundColor Cyan
}

function Get-Sha256([string] $Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Read-PinnedHash([string] $Id) {
    if (-not (Test-Path -LiteralPath $PinFile)) { return $null }
    foreach ($line in Get-Content -LiteralPath $PinFile) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
        $parts = $trimmed -split '\s+', 2
        if ($parts.Count -eq 2 -and $parts[0] -eq $Id) {
            return $parts[1].Trim().ToLowerInvariant()
        }
    }
    return $null
}

function Add-PinnedHash([string] $Id, [string] $Hash) {
    if (-not (Test-Path -LiteralPath $PinFile)) {
        $header = @(
            '# SHA-256 of the official CPython embeddable archives this project builds on.',
            '# Verify a new line against the release page on python.org before adding it:',
            '#   https://www.python.org/downloads/release/python-<version-without-dots>/',
            '# Format: <version>-<arch>  <sha256>',
            ''
        )
        Set-Content -LiteralPath $PinFile -Value $header -Encoding ascii
    }
    Add-Content -LiteralPath $PinFile -Value "$Id  $Hash" -Encoding ascii
    Write-Step "pinned $Id -> $Hash"
}

# --------------------------------------------------------------------------- #
# 1. Sanity-check the tree we are building from
# --------------------------------------------------------------------------- #
foreach ($name in $PayloadFromRoot) {
    $path = Join-Path $RepoRoot $name
    if (-not (Test-Path -LiteralPath $path)) {
        throw "missing payload file: $path"
    }
}
foreach ($name in $PayloadDirs) {
    $path = Join-Path $RepoRoot $name
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        throw "missing payload directory: $path"
    }
}
foreach ($path in @($ZipWriter, $BatSource)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "missing build input: $path"
    }
}

$ToolVersion = 'unknown'
foreach ($line in Get-Content -LiteralPath (Join-Path $RepoRoot 'fw2sbom.py')) {
    if ($line -match '^TOOL_VERSION\s*=\s*"([^"]+)"') {
        $ToolVersion = $Matches[1]
        break
    }
}
Write-Step "fw2sbom $ToolVersion + CPython $PythonVersion ($Architecture)"

# --------------------------------------------------------------------------- #
# 2. Obtain and verify the embeddable interpreter
# --------------------------------------------------------------------------- #
if ($EmbedZip) {
    if (-not (Test-Path -LiteralPath $EmbedZip)) {
        throw "-EmbedZip not found: $EmbedZip"
    }
    $embedPath = (Resolve-Path -LiteralPath $EmbedZip).Path
    Write-Step "using local archive $embedPath"
} else {
    if (-not (Test-Path -LiteralPath $CacheDir)) {
        New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null
    }
    $embedPath = Join-Path $CacheDir $EmbedName
    if (Test-Path -LiteralPath $embedPath) {
        Write-Step "cache hit: $embedPath"
    } else {
        Write-Step "downloading $EmbedUrl"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $progress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try {
            Invoke-WebRequest -Uri $EmbedUrl -OutFile $embedPath -UseBasicParsing
        } finally {
            $ProgressPreference = $progress
        }
    }
}

$actualHash = Get-Sha256 $embedPath
$pinnedHash = Read-PinnedHash $PackageId

if ($pinnedHash) {
    if ($actualHash -ne $pinnedHash) {
        Remove-Item -LiteralPath $embedPath -Force -ErrorAction SilentlyContinue
        throw ("SHA-256 mismatch for ${EmbedName}: expected $pinnedHash, got $actualHash. " +
               'The cached copy has been deleted. Do not build from these bytes.')
    }
    Write-Step "SHA-256 verified against pin: $actualHash"
} elseif ($PinHash) {
    Add-PinnedHash $PackageId $actualHash
} else {
    Write-Warning ("no pinned hash for $PackageId; this build is NOT verified. " +
                   "Its SHA-256 is $actualHash -- check that against " +
                   'https://www.python.org/downloads/ and re-run with -PinHash to record it.')
}

# --------------------------------------------------------------------------- #
# 3. Stage: interpreter, then fw2sbom's files beside it
# --------------------------------------------------------------------------- #
if (Test-Path -LiteralPath $StageDir) {
    Write-Step "clearing $StageDir"
    Remove-Item -LiteralPath $StageDir -Recurse -Force
}
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

Write-Step 'expanding interpreter'
Expand-Archive -LiteralPath $embedPath -DestinationPath $StageDir -Force

Write-Step 'copying fw2sbom files'
foreach ($name in $PayloadFromRoot) {
    Copy-Item -LiteralPath (Join-Path $RepoRoot $name) -Destination $StageDir -Force
}
foreach ($name in $PayloadDirs) {
    Copy-Item -LiteralPath (Join-Path $RepoRoot $name) -Destination $StageDir `
        -Recurse -Force
}
Copy-Item -LiteralPath $BatSource -Destination $StageDir -Force

$stagedPython = Join-Path $StageDir 'python.exe'
if (-not (Test-Path -LiteralPath $stagedPython)) {
    throw "python.exe missing from $StageDir -- wrong archive layout?"
}

# --------------------------------------------------------------------------- #
# 4. Smoke-test the staged package with its own interpreter
# --------------------------------------------------------------------------- #
# -B throughout: a .pyc records the source mtime it was built from, so letting
# the smoke test write __pycache__ into the staging directory would both ship
# the customer our build cache and make the package hash unreproducible.
if ($SkipSmokeTest) {
    Write-Step 'smoke test skipped'
} else {
    Write-Step 'smoke test: staged interpreter runs staged fw2sbom'
    $reported = & $stagedPython '-B' (Join-Path $StageDir 'fw2sbom.py') '--version' 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "staged fw2sbom.py --version failed (exit $LASTEXITCODE): $reported"
    }
    $expected = "fw2sbom $ToolVersion"
    if ("$reported".Trim() -ne $expected) {
        throw "staged fw2sbom reported '$reported', expected '$expected'"
    }
    Write-Step "  $expected"

    # service.py is the actual entry point; importing it catches a missing
    # .pyd or a stdlib module the embeddable build leaves out, which
    # fw2sbom.py alone would not.
    & $stagedPython '-B' '-c' 'import service' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "staged interpreter cannot import service.py (exit $LASTEXITCODE)"
    }
    Write-Step '  service.py imports cleanly'

    # Both SBOM formats come from the same analysis; a missing spdx_report.py
    # would only surface when a customer clicked the SPDX download.
    & $stagedPython '-B' '-c' 'import spdx_report' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "staged interpreter cannot import spdx_report.py (exit $LASTEXITCODE)"
    }
    Write-Step '  spdx_report.py imports cleanly'

    # A package whose component database did not arrive starts up and then
    # reports "no components" for every firmware it is given. Prove the packs
    # load from inside the staged tree, where the paths are what a customer
    # will actually have.
    $loaded = & $stagedPython '-B' '-c' `
        'import fw2sbom; print(len(fw2sbom.load_signatures()))'
    if ($LASTEXITCODE -ne 0) {
        throw "staged package cannot load its signature database (exit $LASTEXITCODE)"
    }
    if ([int]$loaded -lt 1) {
        throw "staged package loaded $loaded signatures"
    }
    Write-Step "  $loaded signatures load from the staged package"
}

# Belt and braces: -B covers what this script runs, but anything that touched
# the staging directory beforehand may have left a cache behind.
$caches = @(Get-ChildItem -LiteralPath $StageDir -Recurse -Force -Directory -Filter '__pycache__' -ErrorAction SilentlyContinue)
foreach ($cache in $caches) {
    Write-Step "removing stray $($cache.FullName)"
    Remove-Item -LiteralPath $cache.FullName -Recurse -Force
}

# --------------------------------------------------------------------------- #
# 5. Archive reproducibly, using the interpreter we just staged
# --------------------------------------------------------------------------- #
if (Test-Path -LiteralPath $ZipPath) {
    Remove-Item -LiteralPath $ZipPath -Force
}
Write-Step 'writing deterministic archive'
& $stagedPython $ZipWriter $StageDir $ZipPath
if ($LASTEXITCODE -ne 0) {
    throw "deterministic zip writer failed (exit $LASTEXITCODE)"
}

# --------------------------------------------------------------------------- #
# 6. Report what to paste into RELEASE.md
# --------------------------------------------------------------------------- #
$zipHash = Get-Sha256 $ZipPath
$zipSize = (Get-Item -LiteralPath $ZipPath).Length

Write-Host ''
Write-Host 'Portable package built' -ForegroundColor Green
Write-Host "  path      $ZipPath"
Write-Host "  size      $zipSize bytes"
Write-Host "  sha256    $zipHash"
Write-Host "  fw2sbom   $ToolVersion"
Write-Host "  cpython   $PythonVersion ($Architecture)"
Write-Host ''
Write-Host 'Payload file hashes (the part that is ours):'
$ourFiles = @($PayloadFromRoot) + @('Start-fw2sbom.bat')
foreach ($name in $PayloadDirs) {
    $ourFiles += Get-ChildItem -LiteralPath (Join-Path $StageDir $name) -Recurse -File |
        ForEach-Object { "$name/" + $_.Name }
}
foreach ($name in $ourFiles) {
    $h = Get-Sha256 (Join-Path $StageDir $name)
    Write-Host ("  {0,-32} {1}" -f $name, $h)
}
Write-Host ''
Write-Host 'Record these in RELEASE.md along with the commit they were built from.'
