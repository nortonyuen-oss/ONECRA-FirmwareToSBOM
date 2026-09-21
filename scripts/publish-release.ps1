<#
.SYNOPSIS
    Publish the built portable package as a GitHub Release asset.

.DESCRIPTION
    Publishes the download. Since v1.20.0 the download page's button points
    straight at the release asset, so this step is part of every release, not
    an extra - without it the button has nothing to serve. Two things come
    with serving it from a release:

      * GitHub counts downloads of release assets on its own servers, which is
        the only real download number a static site can show. The download
        page picks it up automatically once an asset with the expected
        filename exists.

      * Release assets do not live in git history, so a release no longer
        adds ~11 MB to the repository.

    Order matters: push the tag, run this, and only then push master. Pages
    publishes master, and a page pointing at an asset that does not exist yet
    is a download button that 404s.

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
    foreach ($line in Get-Content -LiteralPath (Join-Path $RepoRoot 'fw2sbom.py') -Encoding UTF8) {
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
    # -Encoding UTF8 is not optional. Windows PowerShell 5.1 reads with the
    # system ANSI codepage, which on a Traditional Chinese Windows is Big5:
    # RELEASE.md is UTF-8, so every Chinese character comes back as mojibake
    # and the release notes published to customers are garbage. It also
    # inflates the text - the v1.15.1 section read 1,276 characters that way
    # against its real 1,129.
    $text = Get-Content -LiteralPath $Record -Raw -Encoding UTF8
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
# 2b. Check the token can actually do this, before trying
# --------------------------------------------------------------------------- #
# GitHub answers every one of these problems with the same 403 - "Resource not
# accessible by personal access token" - which does not say whether the token
# is the wrong account, the wrong repository, or the right one with too few
# permissions. Asking two cheap questions first turns that into an answer.
$api = "https://api.github.com/repos/$Repository"
try {
    $whoami = Invoke-WebRequest -Uri 'https://api.github.com/user' `
        -Headers $headers -UseBasicParsing
} catch {
    throw ("the token was rejected by GitHub ($($_.Exception.Response.StatusCode)). " +
           'Check it was copied whole, and has not expired or been revoked.')
}
$account = (ConvertFrom-Json $whoami.Content).login
$scopes  = $whoami.Headers['X-OAuth-Scopes']
Write-Step "token belongs to $account$(if ($scopes) { " (classic, scopes: $scopes)" } else { ' (fine-grained)' })"

$owner = $Repository.Split('/')[0]
try {
    $repoInfo = Invoke-RestMethod -Uri $api -Headers $headers
} catch {
    throw ("this token cannot even see $Repository. " +
           $(if ($account -ne $owner) {
               "It belongs to '$account' but the repository belongs to " +
               "'$owner' - a fine-grained token only reaches repositories " +
               "owned by the account that created it, so make the token while " +
               "signed in as '$owner'."
             } else {
               'Give it access to this repository under Repository access.'
             }))
}
if (-not $repoInfo.permissions.push) {
    throw ("the token can read $Repository but not write to it, and creating " +
           'a release is a write. Fine-grained: Repository permissions -> ' +
           'Contents -> Read and write. Classic: the `repo` scope (or ' +
           '`public_repo` for a public repository).' +
           $(if ($account -ne $owner) {
               " Note it belongs to '$account', not '$owner'."
             } else { '' }))
}
Write-Step "token can write to $Repository"
$release = $null
try {
    $release = Invoke-RestMethod -Uri "$api/releases/tags/$Tag" -Headers $headers
    Write-Step "release for $Tag already exists (id $($release.id))"
} catch {
    # "Get a release by tag name" only finds *published* releases, so a draft
    # left by an earlier run is invisible to it and a second run would quietly
    # create a second draft of the same version. Listing releases with this
    # token does show drafts.
    $drafts = @(Invoke-RestMethod -Uri "$api/releases?per_page=100" -Headers $headers |
                Where-Object { $_.tag_name -eq $Tag })
    if ($drafts.Count -gt 0) {
        $release = $drafts[0]
        Write-Step ("reusing the existing draft for $Tag (id $($release.id)) " +
                    'instead of making a second one')
    }
}

if (-not $release) {
    Write-Step "creating release for $Tag"
    $json = @{
        tag_name = $Tag
        name     = "fw2sbom $Version"
        body     = $notes
        draft    = [bool]$Draft
    } | ConvertTo-Json -Depth 4

    # Send bytes, not a string. Handed a string, Windows PowerShell 5.1 writes
    # it as UTF-8 while setting Content-Length from the *character* count, so
    # any non-ASCII body arrives at the server truncated - which GitHub reports
    # as `{"message":"Problems parsing JSON"}` with no hint of the cause.
    # Encoding here makes the two agree.
    $payload = [System.Text.Encoding]::UTF8.GetBytes($json)
    $release = Invoke-RestMethod -Uri "$api/releases" -Headers $headers `
        -Method Post -Body $payload -ContentType 'application/json; charset=utf-8'
    Write-Step "created (id $($release.id))"

    # The notes are the point of the release. Silently publishing a mangled
    # copy is worse than failing, because nobody rereads their own changelog
    # on someone else's site.
    if ($release.body -ne $notes) {
        Write-Warning ("the notes GitHub stored differ from RELEASE.md - check " +
                       "$($release.html_url) before publishing this draft")
    } else {
        Write-Step 'notes stored intact (byte-for-byte with RELEASE.md)'
    }
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
# Through the API, not the public browser_download_url: that URL does not exist
# until a release is published, so verifying a draft through it fails with a
# bare "Not Found" after a perfectly good upload. The API URL serves the bytes
# GitHub actually stored, draft or not.
$fetch = @{
    Authorization          = "Bearer $token"
    Accept                 = 'application/octet-stream'
    'X-GitHub-Api-Version' = '2022-11-28'
    'User-Agent'           = 'fw2sbom-publish-release'
}
try {
    Invoke-WebRequest -Uri $asset.url -Headers $fetch -OutFile $temp -UseBasicParsing
    $roundTrip = (Get-FileHash -Algorithm SHA256 -LiteralPath $temp).Hash.ToLowerInvariant()
    if ($roundTrip -ne $hash) {
        throw "downloaded asset hashes to $roundTrip, not $hash"
    }
    Write-Step 'hash matches what the download page publishes'
} finally {
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
}

Write-Host ''
if ($release.draft) {
    Write-Host 'Uploaded to a DRAFT release - nobody else can see it yet' -ForegroundColor Yellow
    Write-Host '  Look it over, then press "Publish release" on that page.'
    Write-Host '  Until you do, the download page keeps serving its own copy and'
    Write-Host '  the download counter stays hidden.'
} else {
    Write-Host 'Published' -ForegroundColor Green
}
Write-Host "  release   $($release.html_url)"
Write-Host "  asset     $($asset.browser_download_url)"
Write-Host "  sha256    $hash"
Write-Host ''
Write-Host 'Next: push master (git push origin master). Pages then publishes the'
Write-Host 'download page for this version, whose button points at this asset.'
if ($Draft) {
    Write-Host ''
    Write-Warning 'This is a DRAFT. It stays invisible to the API until you publish it.'
}
