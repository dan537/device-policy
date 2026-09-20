#Requires -Version 5.1
<#
.SYNOPSIS
    Pushes the phone-guard DNS policy to NextDNS profiles via the API.

.DESCRIPTION
    Reads C:\phone-guard\.env for NEXTDNS_API_KEY, NEXTDNS_PROFILE_PHONE and
    NEXTDNS_PROFILE_PC, then applies:

      security          all protective toggles on (both profiles)
      parentalControl   porn category + SafeSearch + blockBypass (both);
                        reddit/discord/telegram services (phone only)
      privacy           ad/tracker blocklists (both) + NSFW list (phone)
      denylist          blocklists\*.txt merged per profile
      allowlist         allow-health.txt (both profiles: the same
                        misclassification applies on the PC)
      settings          block page enabled

    The API key is never printed. Per-call failures are reported without
    aborting the run, so one bad domain can't block the rest.

.USAGE
    powershell -ExecutionPolicy Bypass -File scripts\nextdns-sync.ps1
    powershell -ExecutionPolicy Bypass -File scripts\nextdns-sync.ps1 -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$EnvFile = (Join-Path $PSScriptRoot '..\.env'),
    [string]$ListDir = (Join-Path $PSScriptRoot '..\blocklists')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ApiBase = 'https://api.nextdns.io'

# --------------------------------------------------------------------------
# .env parsing
# --------------------------------------------------------------------------
function Read-DotEnv([string]$Path) {
    if (-not (Test-Path $Path)) { throw ".env not found at $Path. Copy .env.example and fill in NEXTDNS_API_KEY." }
    $map = @{}
    foreach ($line in Get-Content $Path) {
        $line = $line.Trim()
        if ($line -eq '' -or $line.StartsWith('#')) { continue }
        $i = $line.IndexOf('=')
        if ($i -lt 1) { continue }
        $map[$line.Substring(0, $i).Trim()] = $line.Substring($i + 1).Trim()
    }
    return $map
}

# --------------------------------------------------------------------------
# Blocklist file parsing: strip comments/blank lines, lowercase, dedupe.
# --------------------------------------------------------------------------
function Read-ListFile([string[]]$Names) {
    $out = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $Names) {
        $p = Join-Path $ListDir $n
        if (-not (Test-Path $p)) { Write-Warning "list file missing: $p"; continue }
        foreach ($line in Get-Content $p) {
            $line = $line.Trim()
            if ($line -eq '' -or $line.StartsWith('#')) { continue }
            [void]$out.Add($line.ToLowerInvariant())
        }
    }
    return @($out | Sort-Object)
}

# --------------------------------------------------------------------------
# API plumbing. Returns the decoded response; records failures in $script:Failures.
# --------------------------------------------------------------------------
$script:Failures = [System.Collections.Generic.List[string]]::new()

function Invoke-NextDns([string]$Method, [string]$Path, $Body = $null, [string]$Context = '') {
    $uri = "$ApiBase$Path"
    $params = @{
        Method      = $Method
        Uri         = $uri
        Headers     = @{ 'X-Api-Key' = $script:ApiKey }
        ContentType = 'application/json'
    }
    if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 10 -Compress) }
    try {
        $resp = Invoke-RestMethod @params
        if ($resp.errors) {
            $detail = ($resp.errors | ForEach-Object { $_.detail }) -join '; '
            $script:Failures.Add("$Context $Method $Path -> $detail")
            return $null
        }
        return $resp
    } catch {
        $script:Failures.Add("$Context $Method $Path -> $($_.Exception.Message)")
        return $null
    }
}

function Get-AllPages([string]$Path, [string]$Context) {
    $items = [System.Collections.Generic.List[object]]::new()
    $cursor = $null
    do {
        if ($Path -match '\?') { $sep = '&' } else { $sep = '?' }
        $p = $Path + $sep + 'limit=500'
        if ($cursor) { $p += "&cursor=$cursor" }
        $resp = Invoke-NextDns 'GET' $p -Context $Context
        if ($null -eq $resp) { return $items }
        if ($resp.data) { $items.AddRange(@($resp.data)) }
        $cursor = $resp.meta.pagination.cursor
    } while ($cursor)
    return $items
}

# --------------------------------------------------------------------------
# Sync a domain list (denylist or allowlist): add missing, re-enable disabled.
# --------------------------------------------------------------------------
function Sync-DomainList([string]$Profile, [string]$Kind, [string[]]$Wanted) {
    $current = Get-AllPages "/profiles/$Profile/$Kind" $Kind
    $active = @{}; $inactive = @{}
    foreach ($e in $current) {
        if ($e.active) { $active[$e.id] = $true } else { $inactive[$e.id] = $true }
    }
    $added = 0; $reactivated = 0; $ok = 0
    foreach ($d in $Wanted) {
        if ($active.ContainsKey($d)) { $ok++; continue }
        if ($inactive.ContainsKey($d)) {
            $enc = [uri]::EscapeDataString($d)
            if (Invoke-NextDns 'PATCH' "/profiles/$Profile/$Kind/$enc" @{ active = $true } $Kind) { $reactivated++ }
            continue
        }
        if (Invoke-NextDns 'POST' "/profiles/$Profile/$Kind" @{ id = $d; active = $true } $Kind) { $added++ }
    }
    Write-Host ("    {0,-9} wanted {1,3} | added {2,3} | reactivated {3} | already ok {4}" -f $Kind, $Wanted.Count, $added, $reactivated, $ok)
}

function Sync-Blocklists([string]$Profile, [string[]]$Ids) {
    $current = Get-AllPages "/profiles/$Profile/privacy/blocklists" 'blocklists'
    $have = @{}
    foreach ($e in $current) { $have[$e.id] = $true }
    $added = 0
    foreach ($id in $Ids) {
        if ($have.ContainsKey($id)) { continue }
        if (Invoke-NextDns 'POST' "/profiles/$Profile/privacy/blocklists" @{ id = $id } 'blocklists') { $added++ }
    }
    Write-Host ("    blocklists wanted {0} | added {1}" -f $Ids.Count, $added)
}

# --------------------------------------------------------------------------
# Policy definitions
# --------------------------------------------------------------------------
$Security = @{
    threatIntelligenceFeeds = $true
    aiThreatDetection       = $true
    googleSafeBrowsing      = $true
    cryptojacking           = $true
    dnsRebinding            = $true
    idnHomographs           = $true
    typosquatting           = $true
    dga                     = $true
    nrd                     = $true
    ddns                    = $true
    parking                 = $true
    csam                    = $true
}

$BlocklistsShared = @('nextdns-recommended', 'oisd')
$BlocklistsPhone  = $BlocklistsShared + @('oisd-nsfw')

$ParentalPc = @{
    categories = @(@{ id = 'porn'; active = $true })
    services   = @()
    safeSearch = $true
    youtubeRestrictedMode = $false
    blockBypass = $true
}
$ParentalPhone = @{
    categories = @(@{ id = 'porn'; active = $true })
    services   = @(
        @{ id = 'reddit';   active = $true },
        @{ id = 'discord';  active = $true },
        @{ id = 'telegram'; active = $true }
    )
    safeSearch = $true
    youtubeRestrictedMode = $false
    blockBypass = $true
}

$Settings = @{ blockPage = @{ enabled = $true } }

$DenyShared = Read-ListFile 'deny-porn.txt', 'deny-bypass.txt', 'deny-reddit.txt'
$DenyPhone  = $DenyShared + (Read-ListFile 'deny-phone-only.txt')
$AllowHealth = Read-ListFile 'allow-health.txt'

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
$env_ = Read-DotEnv $EnvFile
$script:ApiKey = $env_['NEXTDNS_API_KEY']
if ([string]::IsNullOrWhiteSpace($script:ApiKey)) {
    throw "NEXTDNS_API_KEY is empty in $EnvFile. Paste the key from https://my.nextdns.io/account (bottom of page) into that file. Do NOT paste it anywhere else."
}

$profiles = @(
    @{ Id = $env_['NEXTDNS_PROFILE_PHONE']; Label = 'PHONE (strict)';
       Parental = $ParentalPhone; Blocklists = $BlocklistsPhone; Deny = $DenyPhone; Allow = $AllowHealth },
    @{ Id = $env_['NEXTDNS_PROFILE_PC'];    Label = 'PC (moderate)';
       Parental = $ParentalPc;    Blocklists = $BlocklistsShared; Deny = $DenyShared; Allow = $AllowHealth }
)

foreach ($p in $profiles) {
    if ([string]::IsNullOrWhiteSpace($p.Id)) { Write-Warning "$($p.Label): profile id missing in .env, skipped"; continue }
    Write-Host ""
    Write-Host "== $($p.Label)  profile $($p.Id) =="
    if ($WhatIfPreference) { Write-Host "    (WhatIf: no changes sent)"; continue }

    if (Invoke-NextDns 'PATCH' "/profiles/$($p.Id)/security" $Security 'security') { Write-Host "    security: applied" }
    if (Invoke-NextDns 'PATCH' "/profiles/$($p.Id)/parentalControl" $p.Parental 'parentalControl') { Write-Host "    parentalControl: applied" }
    Sync-Blocklists $p.Id $p.Blocklists
    Sync-DomainList $p.Id 'denylist' $p.Deny
    Sync-DomainList $p.Id 'allowlist' $p.Allow
    if (Invoke-NextDns 'PATCH' "/profiles/$($p.Id)/settings" $Settings 'settings') { Write-Host "    settings: applied" }
}

Write-Host ""
if ($script:Failures.Count -gt 0) {
    Write-Host "FAILURES ($($script:Failures.Count)):" -ForegroundColor Yellow
    $script:Failures | ForEach-Object { Write-Host "  $_" }
    exit 1
} else {
    Write-Host "All changes applied cleanly." -ForegroundColor Green
}
