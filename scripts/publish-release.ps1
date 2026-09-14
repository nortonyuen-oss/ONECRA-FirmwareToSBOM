<#
.SYNOPSIS
    Publish the built portable package as a GitHub Release asset.

.DESCRIPTION
    Moves the download off GitHub Pages and onto a release asset. Two things
    come with that:

      * GitHub counts downloads of release assets on its own servers, which is
        the only real download number a static site can show. The download
        page picks it up automatically once an asset with the expected
        filename exists.

      * Release assets do not live in git history, so the ~11 MB per release
        currently committed under docs/downloads/ stops accumulating.

    **Your token never reaches the script's output or anyone else.** It is read
    from $env:GITHUB_TOKEN, used for the two API calls, and never printed,
    logged or written to a file. Set it in your own shell:

        $env:GITHUB_TOKEN = "ghp_..."      # needs the `repo` scope
        .\scripts\publish-release.ps1

    Create one at https://github.com/settings/tokens (classic, `repo` scope, or
    a fine-grained token with Contents: read and write on this repository).
    Revoke it afterwards if you would rather not keep one around.

    The release body is taken from the matching section of RELEASE.md, so the
    published notes and the build record cannot drift apart.

.PARAMETER Version
    Defaults to TOOL_VERSION in fw2sbom.py. The tag v<Version> must exist and
    be pushed.

.PARAMETER Draft
    Create the release as a draft so you can look at it before it goes public.
#>
[CmdletBinding()]
param(
    [string] $Version,
    [string] $Repository = 'nortonyuen-oss/ONECRA-FirmwareToSBOM',
    [switch] $Draft
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ZipPath  = Join-Path $RepoRoot 'dist-portable/fw2sbom-portable.zip'
$Record   = Join-Path $RepoRoot 'RELEASE.md'

function Write-Step([string] $Message) {
    Write-Host "[release] $Message" -ForegroundColor Cyan
}

# --------------------------------------------------------------------------- #
# 1. Work out what we are publishing
# --------------------------------------------------------------------------- #
if (-not $Version) {
    foreach ($line in Get-Content -LiteralPath (Join-Path $RepoRoot 'fw2sbom.py')) {
        if ($line -match '^TOOL_VERSION\s*=\s*"([^"]+)"') { $Version = $Matches[1]; break }
    }
}
if (-not $Version) { throw 'cannot determine the version; pass -Version' }

$Tag       = "v$Version"
$AssetName = "fw2sbom-portable-$Version.zip"

if (-not (Test-Path -LiteralPath $ZipPath)) {
    throw "no package at $ZipPath - run .\scripts\build-portable.ps1 first"
}
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ZipPath).Hash.ToLowerInvariant()
$size = (Get-Item -LiteralPath $ZipPath).Length
Write-Step "$Tag  $AssetName  $size bytes"
Write-Step "sha256 $hash"

# The record is the source of truth for what this build is; if it does not
# describe this version, the release notes would be inventing something.
$notes = $null
if (Test-Path -LiteralPath $Record) {
    $text = Get-Content -LiteralPath $Record -Raw
    $pattern = "(?ms)^## $([regex]::Escape($Tag))\r?\n(.*?)(?=^## v|\z)"
    $match = [regex]::Match($text, $pattern)
    if ($match.Success) { $notes = $match.Groups[1].Value.Trim() }
}
if (-not $notes) {
    throw "RELEASE.md has no section for $Tag - add it before publishing"
}
if ($notes -notlike "*$hash*") {
    throw ("RELEASE.md's $Tag section does not mention the hash of the package " +
           "you are about to upload. Rebuild, or update the record, so the two agree.")
}
Write-Step "release notes taken from RELEASE.md ($($notes.Length) chars)"

# --------------------------------------------------------------------------- #
# 2. Authenticate
# --------------------------------------------------------------------------- #
$token = $env:GITHUB_TOKEN
if (-not $token) {
    throw ('set $env:GITHUB_TOKEN first (needs the `repo` scope). It is used ' +
           'for two API calls and never printed or stored by this script.')
}
$headers = @{
    Authorization          = "Bearer $token"
    Accept                 = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
    'User-Agent'           = 'fw2sbom-publish-release'
}

# --------------------------------------------------------------------------- #
# 3. Create the release, or reuse one already there
# --------------------------------------------------------------------------- #
$api = "https://api.github.com/repos/$Repository"
$release = $null
try {
    $release = Invoke-RestMethod -Uri "$api/releases/tags/$Tag" -Headers $headers
    Write-Step "release for $Tag already exists (id $($release.id))"
} catch {
    Write-Step "creating release for $Tag"
    $body = @{
        tag_name = $Tag
        name     = "fw2sbom $Version"
        body     = $notes
        draft    = [bool]$Draft
    } | ConvertTo-Json -Depth 4
    $release = Invoke-RestMethod -Uri "$api/releases" -Headers $headers `
        -Method Post -Body $body -ContentType 'application/json'
    Write-Step "created (id $($release.id))"
}

# --------------------------------------------------------------------------- #
# 4. Upload the asset
# --------------------------------------------------------------------------- #
$existing = @($release.assets | Where-Object { $_.name -eq $AssetName })
if ($existing.Count -gt 0) {
    Write-Step "replacing the existing $AssetName"
    Invoke-RestMethod -Uri "$api/releases/assets/$($existing[0].id)" `
        -Headers $headers -Method Delete | Out-Null
}

Write-Step "uploading $AssetName"
$uploadUri = ("https://uploads.github.com/repos/$Repository/releases/" +
              "$($release.id)/assets?name=$AssetName")
$asset = Invoke-RestMethod -Uri $uploadUri -Headers $headers -Method Post `
    -InFile $ZipPath -ContentType 'application/zip'
Write-Step "uploaded ($($asset.size) bytes)"

if ($asset.size -ne $size) {
    throw "uploaded $($asset.size) bytes but the file is $size - do not publish this"
}

# --------------------------------------------------------------------------- #
# 5. Prove the bytes survived the round trip
# --------------------------------------------------------------------------- #
Write-Step 'downloading it back to check the hash'
$temp = Join-Path ([IO.Path]::GetTempPath()) "fw2sbom-verify-$Version.zip"
try {
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $temp -UseBasicParsing
    $roundTrip = (Get-FileHash -Algorithm SHA256 -LiteralPath $temp).Hash.ToLowerInvariant()
    if ($roundTrip -ne $hash) {
        throw "downloaded asset hashes to $roundTrip, not $hash"
    }
    Write-Step 'hash matches what the download page publishes'
} finally {
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host 'Published' -ForegroundColor Green
Write-Host "  release   $($release.html_url)"
Write-Host "  asset     $($asset.browser_download_url)"
Write-Host "  sha256    $hash"
Write-Host ''
Write-Host 'The download page picks this up on its next load: the button repoints'
Write-Host 'at the release asset and the download counter appears.'
if ($Draft) {
    Write-Host ''
    Write-Warning 'This is a DRAFT. It stays invisible to the API until you publish it.'
}
