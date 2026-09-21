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
      denylist          blocklists\*.txt merged per profile (PUT as one
                        array - the API rate-limits per-domain POSTs)
      allowlist         allow-health.txt (both profiles: the same
                        misclassification applies on the PC)
      settings          block page enabled

    Declarative: each array is PUT wholesale, so re-running is idempotent.
    The API key is never printed.

.USAGE
    powershell -ExecutionPolicy Bypass -File scripts\nextdns-sync.ps1
#>

[CmdletBinding()]
param(
    [string]$EnvFile = '',
    [string]$ListDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ApiBase = 'https://api.nextdns.io'

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $EnvFile) { $EnvFile = Join-Path $scriptDir '..\.env' }
if (-not $ListDir) { $ListDir = Join-Path $scriptDir '..\blocklists' }

# --------------------------------------------------------------------------
# Helpers that survive Set-StrictMode (missing-property access throws there).
# --------------------------------------------------------------------------
function Get-Prop($Obj, [string]$Name) {
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -ne $p) { return $p.Value }
    return $null
}

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

# Serialize an object[] as a top-level JSON ARRAY even when it has 0/1 items.
function ConvertTo-JsonArray($Items) {
    $parts = foreach ($i in @($Items)) { $i | ConvertTo-Json -Depth 10 -Compress }
    return '[' + ($parts -join ',') + ']'
}

# --------------------------------------------------------------------------
# API plumbing. Retries 429 with backoff; records failures in $script:Failures.
# --------------------------------------------------------------------------
$script:Failures = [System.Collections.Generic.List[string]]::new()

function Invoke-NextDns([string]$Method, [string]$Path, $Body = $null, [string]$Context = '') {
    $uri = "$ApiBase$Path"
    $json = $null
    if ($null -ne $Body) {
        if ($Body -is [string]) { $json = $Body } else { $json = $Body | ConvertTo-Json -Depth 10 -Compress }
    }
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $params = @{
                Method  = $Method
                Uri     = $uri
                Headers = @{ 'X-Api-Key' = $script:ApiKey }
            }
            if ($null -ne $json) {
                $params['ContentType'] = 'application/json'
                $params['Body'] = $json
            }
            $resp = Invoke-RestMethod @params
            $errs = Get-Prop $resp 'errors'
            if ($errs) {
                $detail = (@($errs) | ForEach-Object { "$(Get-Prop $_ 'code'):$(Get-Prop $_ 'detail')" }) -join '; '
                $script:Failures.Add("$Context $Method $Path -> $detail")
                return $null
            }
            return $resp
        } catch {
            $status = $null
            $detail = $_.Exception.Message
            $httpResp = Get-Prop $_.Exception 'Response'
            if ($null -ne $httpResp) {
                $status = [int](Get-Prop $httpResp 'StatusCode')
                try {
                    $sr = New-Object IO.StreamReader($httpResp.GetResponseStream())
                    $detail = $sr.ReadToEnd()
                } catch { }
            }
            if ($status -eq 429 -and $attempt -le 6) {
                $wait = [Math]::Min(2 * $attempt, 20)
                Write-Host "    429 rate-limited; retry ${attempt}/6 in ${wait}s"
                Start-Sleep -Seconds $wait
                continue
            }
            $script:Failures.Add("$Context $Method $Path -> HTTP $status $detail")
            return $null
        }
    }
}

# PUT a whole array endpoint (denylist, allowlist, privacy/blocklists).
function Sync-ArrayEndpoint([string]$Profile, [string]$Path, [object[]]$Items, [string]$Label) {
    $json = ConvertTo-JsonArray $Items
    if (Invoke-NextDns 'PUT' "/profiles/$Profile/$Path" $json $Label) {
        Write-Host ("    {0,-11} applied ({1} entries)" -f $Label, $Items.Count)
    }
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

# Verified list IDs only — an unknown ID makes the whole PATCH 400.
# NSFW coverage comes from the 'porn' category + our denylist.
$BlocklistsShared = @('nextdns-recommended', 'oisd')
$BlocklistsPhone  = $BlocklistsShared

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

$DenyShared  = Read-ListFile 'deny-porn.txt', 'deny-bypass.txt', 'deny-reddit.txt'
$DenyPhone   = $DenyShared + (Read-ListFile 'deny-phone-only.txt')
$AllowHealth = Read-ListFile 'allow-health.txt'

function To-Entries([string[]]$Domains) { return @($Domains | ForEach-Object { @{ id = $_; active = $true } }) }
function To-Ids([string[]]$Ids)         { return @($Ids | ForEach-Object { @{ id = $_ } }) }

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

    if (Invoke-NextDns 'PATCH' "/profiles/$($p.Id)/security" $Security 'security') { Write-Host "    security applied" }
    if (Invoke-NextDns 'PATCH' "/profiles/$($p.Id)/parentalControl" $p.Parental 'parentalControl') { Write-Host "    parentalControl applied" }
    # privacy is an object endpoint: PATCH {blocklists:[{id}]} rather than
    # PUT on the array child (which 400s).
    if (Invoke-NextDns 'PATCH' "/profiles/$($p.Id)/privacy" @{ blocklists = (To-Ids $p.Blocklists) } 'blocklists') {
        Write-Host ("    {0,-11} applied ({1} lists)" -f 'blocklists', $p.Blocklists.Count)
    }
    Sync-ArrayEndpoint $p.Id 'denylist' (To-Entries $p.Deny) 'denylist'
    Sync-ArrayEndpoint $p.Id 'allowlist' (To-Entries $p.Allow) 'allowlist'
    if (Invoke-NextDns 'PATCH' "/profiles/$($p.Id)/settings" $Settings 'settings') { Write-Host "    settings applied" }

    # Verify: GET the whole profile and count what actually landed.
    $check = Invoke-NextDns 'GET' "/profiles/$($p.Id)" -Context 'verify'
    if ($check) {
        $d = Get-Prop $check 'data'
        $deny = @(Get-Prop $d 'denylist'); $allow = @(Get-Prop $d 'allowlist')
        $cats = @(Get-Prop (Get-Prop $d 'parentalControl') 'categories')
        $svcs = @(Get-Prop (Get-Prop $d 'parentalControl') 'services')
        $bls  = @(Get-Prop (Get-Prop $d 'privacy') 'blocklists')
        $catStr = (@($cats) | ForEach-Object { $_.id }) -join '/'
        $svcStr = (@($svcs) | Where-Object { $_.active } | ForEach-Object { $_.id }) -join '/'
        Write-Host "    verify: denylist=$($deny.Count) allowlist=$($allow.Count) categories=$catStr services=$svcStr blocklists=$($bls.Count)"
    }
}

Write-Host ""
if ($script:Failures.Count -gt 0) {
    Write-Host "FAILURES ($($script:Failures.Count)):" -ForegroundColor Yellow
    $script:Failures | ForEach-Object { Write-Host "  $_" }
    exit 1
} else {
    Write-Host "All changes applied cleanly." -ForegroundColor Green
}
