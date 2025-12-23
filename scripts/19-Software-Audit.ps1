<#
.SYNOPSIS
  Audits installed Windows software against a JSON-based whitelist/blacklist catalog and returns a structured audit result.

.DESCRIPTION
  This script builds a software inventory by reading the Uninstall registry locations (machine-wide 64-bit/32-bit and per-user). 
  The inventory is evaluated against a catalog that contains regex-based allow/deny rules for software names and (optionally) vendors/publishers. 
  The script prints a human-friendly console report (colors, sections, top lists) using host output only, and emits exactly one structured object to the pipeline for further processing (e.g., filtering, exporting, or JSON serialization). 

  Catalog loading order:
  1) -CatalogPath (explicit)
  2) -ConfigPath (reads Software.CatalogPath)
  3) Embedded default catalog (conservative baseline)
  4) Empty catalog (no rules) 

  Result classification:
  - Whitelisted: matches at least one whitelist rule
  - Blacklisted: matches at least one blacklist rule
  - Unknown: matches neither list 

  Exit codes:
  - 0 = OK (EventId 4900): no unknown and no blacklisted entries
  - 1 = Warning (EventId 4901): unknown entries exist (and none are blacklisted)
  - 2 = Error (EventId 4902): blacklisted entries exist, or a runtime error occurred 

.PARAMETER CatalogPath
  Path to a JSON catalog file containing Whitelist and/or Blacklist rule arrays. 
  When provided, this takes precedence over any catalog path found in -ConfigPath. 

  Expected JSON shape (example):
  {
    "Whitelist": [ { "NameRegex": "regex", "VendorRegex": "regex" } ],
    "Blacklist": [ { "NameRegex": "regex", "VendorRegex": "regex" } ]
  } 

  Rules are evaluated using regex matching:
  - NameRegex matches the installed software display name.
  - VendorRegex matches the installed software publisher (optional; empty means "ignore vendor"). 

.PARAMETER ConfigPath
  Path to a JSON configuration file used to discover the catalog path when -CatalogPath is not provided. 
  The script reads Software.CatalogPath from this file (if present) and tries to load the catalog from that location. 

.PARAMETER StatePath
  Path to write the proof/state JSON output (the complete structured result object). 
  If empty string is supplied, writing the proof JSON is disabled. 
  When enabled, the script creates the destination directory if needed. 

.PARAMETER Strict
  Switch that enforces stricter compliance behavior. 
  When set, any drift (Unknown or Blacklisted) results in a non-zero exit code, and Blacklisted always results in Error. 

.INPUTS
  None. 

.OUTPUTS
  System.Management.Automation.PSCustomObject. 
  The script outputs exactly one object with high-level metadata, counts, status, and the full classified software lists (Whitelisted/Unknown/Blacklisted), designed to work cleanly with the pipeline. 

.EXAMPLE
  PS> .\19-Software-Audit.ps1
  Runs the audit using the embedded default catalog (unless ConfigPath points to a valid catalog) and prints the console report. 

.EXAMPLE
  PS> .\19-Software-Audit.ps1 -CatalogPath "PATH/TO/JSON/catalog.json"
  Runs the audit with an explicit catalog file. 

.EXAMPLE
  PS> .\19-Software-Audit.ps1 -ConfigPath "PATH/TO/JSON/config.json"
  Runs the audit and loads the catalog path from Software.CatalogPath in the config file. 

.EXAMPLE
  PS> .\19-Software-Audit.ps1 -StatePath "PATH/TO/PROOF/sw-inventory.json"
  Runs the audit and writes the full result object as proof JSON to the specified path. 

.EXAMPLE
  PS> .\19-Software-Audit.ps1 -StatePath ""
  Runs the audit without writing any proof JSON file. 

.EXAMPLE
  PS> $r = .\19-Software-Audit.ps1; $r.Unknown | Select-Object Name, Version, Publisher
  Captures the structured result object and inspects unknown software entries using normal pipeline operations. 

.EXAMPLE
  PS> .\19-Software-Audit.ps1 | ConvertTo-Json -Depth 7
  Serializes the structured result object to JSON in the pipeline (useful for integrations). 

.EXAMPLE
  PS> .\19-Software-Audit.ps1 | Select-Object -ExpandProperty Blacklisted | Export-Csv "PATH/TO/PROOF/blacklisted.csv" -NoTypeInformation
  Exports only blacklisted entries to CSV. 

.NOTES
  The console output is intended for humans and is emitted via host output; it is not part of the pipeline output. 
  Event logging is best-effort: when the event source is not available, the script writes a fallback log line to a text file. 
  Catalog rules use regex matching; invalid regex patterns can cause evaluation errors and should be tested before deployment. 
#>


[CmdletBinding()]
param(
  [string]$CatalogPath,
  [string]$StatePath  = "PATH\TO\PROOF\sw-inventory.json",
  [switch]$Strict,
  [string]$ConfigPath = "PATH\TO\JSON\config.json"
)

Set-StrictMode -Version 2.0

# -------------------- Settings --------------------
$Script:EventLogName     = 'Application'
$Script:EventSourceName  = 'Software-Audit'
$Script:FallbackEventLog = "PATH\TO\PROOF\sw-inventory.eventlog-fallback.txt"

$Script:DefaultCatalogJson = @"
{
  "Whitelist": [
    { "NameRegex": "^(Microsoft Edge|Microsoft.*Update|PowerShell|Windows PowerShell)", "VendorRegex": "" },
    { "NameRegex": "Visual C..Redistributable", "VendorRegex": "" }
  ],
  "Blacklist": [
    { "NameRegex": "(?i)(teamviewer|anydesk|ultravnc|tightvnc|wireshark|nmap|tor|metasploit)", "VendorRegex": "" }
  ]
}
"@

# -------------------- Helpers: safe property access --------------------
function Test-HasProperty {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]$Object,
    [Parameter(Mandatory=$true)][string]$Name
  )
  if (-not $Object) { return $false }
  return ($Object.PSObject.Properties.Match($Name).Count -gt 0)
}

function Get-PropString {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]$Object,
    [Parameter(Mandatory=$true)][string]$Name
  )
  if (-not (Test-HasProperty -Object $Object -Name $Name)) { return '' }
  return [string]$Object.$Name
}

function Get-PropInt {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]$Object,
    [Parameter(Mandatory=$true)][string]$Name,
    [int]$Default = 0
  )
  if (-not (Test-HasProperty -Object $Object -Name $Name)) { return $Default }
  try { return [int]$Object.$Name } catch { return $Default }
}

# -------------------- Helpers: filesystem + JSON --------------------
function Ensure-Directory {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }

  try {
    if (-not (Test-Path -LiteralPath $Path)) {
      New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    return $true
  } catch {
    return $false
  }
}

function Read-JsonFile {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$Path)

  try {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

    $raw | ConvertFrom-Json -ErrorAction Stop
  } catch {
    return $null
  }
}

function ConvertFrom-JsonSafe {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$Json)

  try {
    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    $Json | ConvertFrom-Json -ErrorAction Stop
  } catch {
    return $null
  }
}

# -------------------- Catalog --------------------
function New-CatalogWrapper {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][bool]$Loaded,
    $CatalogObject
  )

  $wl = @()
  $bl = @()

  if ($CatalogObject -and $CatalogObject.PSObject -and $CatalogObject.PSObject.Properties) {
    if ($CatalogObject.PSObject.Properties.Match('Whitelist').Count -gt 0 -and $CatalogObject.Whitelist) { $wl = @($CatalogObject.Whitelist) }
    if ($CatalogObject.PSObject.Properties.Match('Blacklist').Count -gt 0 -and $CatalogObject.Blacklist) { $bl = @($CatalogObject.Blacklist) }
  }

  if ($wl -eq $null) { $wl = @() }
  if ($bl -eq $null) { $bl = @() }

  [pscustomobject]@{
    Meta      = [pscustomobject]@{ Source = $Source; Loaded = $Loaded }
    Whitelist = @($wl)
    Blacklist = @($bl)
  }
}

function Load-Catalog {
  [CmdletBinding()]
  param(
    [string]$CatalogPath,
    [string]$ConfigPath
  )

  if (-not [string]::IsNullOrWhiteSpace($CatalogPath)) {
    $cat = Read-JsonFile -Path $CatalogPath
    if ($cat) { return (New-CatalogWrapper -Source 'CatalogPath' -Loaded $true -CatalogObject $cat) }
  }

  if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
    $cfg = Read-JsonFile -Path $ConfigPath
    if ($cfg -and (Test-HasProperty $cfg 'Software') -and $cfg.Software -and (Test-HasProperty $cfg.Software 'CatalogPath')) {
      $p = [string]$cfg.Software.CatalogPath
      if (-not [string]::IsNullOrWhiteSpace($p)) {
        $cat = Read-JsonFile -Path $p
        if ($cat) { return (New-CatalogWrapper -Source 'ConfigPath:Software.CatalogPath' -Loaded $true -CatalogObject $cat) }
      }
    }
  }

  $fallback = ConvertFrom-JsonSafe -Json $Script:DefaultCatalogJson
  if ($fallback) { return (New-CatalogWrapper -Source 'EmbeddedDefault' -Loaded $true -CatalogObject $fallback) }

  New-CatalogWrapper -Source 'EmptyFallback' -Loaded $false -CatalogObject $null
}

# -------------------- Event logging (best effort) --------------------
function Ensure-EventSource {
  [CmdletBinding()]
  param(
    [string]$Source = $Script:EventSourceName,
    [string]$Log    = $Script:EventLogName
  )

  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
      New-EventLog -LogName $Log -Source $Source -ErrorAction Stop
    }
    return $true
  } catch {
    return $false
  }
}

function Write-HealthEvent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][int]$Id,
    [Parameter(Mandatory=$true)][string]$Msg,
    [ValidateSet('Information','Warning','Error')]$Level = 'Information',
    [string]$Source = $Script:EventSourceName,
    [string]$FallbackPath = $Script:FallbackEventLog
  )

  # Write-EventLog requires -Message to be a string.
  $safeMsg = [string]$Msg

  try {
    Write-EventLog -LogName $Script:EventLogName -Source $Source -EntryType $Level -EventId $Id -Message $safeMsg -ErrorAction Stop
    return $true
  } catch {
    try {
      $dir = Split-Path -Parent $FallbackPath
      if ($dir) { Ensure-Directory -Path $dir | Out-Null }
      ("{0} [{1}] [{2}] {3}" -f (Get-Date).ToString('s'), $Level, $Id, $safeMsg) |
        Add-Content -Encoding UTF8 -LiteralPath $FallbackPath
    } catch {}
    return $false
  }
}

# -------------------- Inventory (pipeline-friendly) --------------------
function Get-InstalledSoftware {
  [CmdletBinding()]
  param()

  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
  )

  $items = @()

  foreach ($p in $paths) {
    $subKeys = Get-ChildItem -Path $p -ErrorAction SilentlyContinue
    foreach ($sk in $subKeys) {
      $v = Get-ItemProperty -Path $sk.PSPath -ErrorAction SilentlyContinue
      if (-not $v) { continue }

      if (-not (Test-HasProperty -Object $v -Name 'DisplayName')) { continue }
      $displayName = Get-PropString -Object $v -Name 'DisplayName'
      if ([string]::IsNullOrWhiteSpace($displayName)) { continue }

      $systemComponent = Get-PropInt -Object $v -Name 'SystemComponent' -Default 0
      if ($systemComponent -eq 1) { continue }

      $parentKeyName = Get-PropString -Object $v -Name 'ParentKeyName'
      if (-not [string]::IsNullOrWhiteSpace($parentKeyName)) { continue }

      $releaseType = Get-PropString -Object $v -Name 'ReleaseType'
      if (-not [string]::IsNullOrWhiteSpace($releaseType) -and ($releaseType -match 'Update|Hotfix|Security Update')) { continue }

      $items += [pscustomobject]@{
        Name            = $displayName
        Version         = Get-PropString -Object $v -Name 'DisplayVersion'
        Publisher       = Get-PropString -Object $v -Name 'Publisher'
        UninstallString = Get-PropString -Object $v -Name 'UninstallString'
        InstallDate     = Get-PropString -Object $v -Name 'InstallDate'
        Key             = [string]$sk.PSChildName
        HivePath        = [string]$p
        Source          = 'Registry'
      }
    }
  }

  $dedup = @{}
  foreach ($it in $items) {
    $k = ("{0}||{1}||{2}" -f $it.Name, $it.Version, $it.Publisher)
    if (-not $dedup.ContainsKey($k)) { $dedup[$k] = $it }
  }

  $dedup.Values | Sort-Object Name, Version
}

# -------------------- Compliance evaluation (pipeline-friendly) --------------------
function Test-SoftwareCompliance {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]$Inventory,
    [Parameter(Mandatory=$true)]$Catalog
  )

  $whitelist = @($Catalog.Whitelist)
  $blacklist = @($Catalog.Blacklist)

  $BLHits  = @()
  $WLHits  = @()
  $Unknown = @()

  foreach ($sw in $Inventory) {
    $name = [string]$sw.Name
    $pub  = [string]$sw.Publisher

    $WLMatch = $false
    foreach ($w in $whitelist) {
      $nr = [string]$w.NameRegex
      $vr = [string]$w.VendorRegex
      $nOk = ([string]::IsNullOrWhiteSpace($nr)) -or ($name -match $nr)
      $pOk = ([string]::IsNullOrWhiteSpace($vr)) -or ($pub  -match $vr)
      if ($nOk -and $pOk) { $WLMatch = $true; break }
    }

    $BLMatch = $false
    foreach ($b in $blacklist) {
      $nr = [string]$b.NameRegex
      $vr = [string]$b.VendorRegex
      $nOk = ([string]::IsNullOrWhiteSpace($nr)) -or ($name -match $nr)
      $pOk = ([string]::IsNullOrWhiteSpace($vr)) -or ($pub  -match $vr)
      if ($nOk -and $pOk) { $BLMatch = $true; break }
    }

    if ($BLMatch)      { $BLHits  += $sw }
    elseif ($WLMatch)  { $WLHits  += $sw }
    else               { $Unknown += $sw }
  }

  [pscustomobject]@{
    Blacklisted = @($BLHits)
    Whitelisted = @($WLHits)
    Unknown     = @($Unknown)
  }
}

function Get-AuditStatus {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][int]$BlacklistedCount,
    [Parameter(Mandatory=$true)][int]$UnknownCount,
    [switch]$Strict
  )

  $eventId = 4900
  $level   = 'Information'

  if ($BlacklistedCount -gt 0) {
    $eventId = 4902; $level = 'Error'
  } elseif ($UnknownCount -gt 0) {
    $eventId = 4901; $level = 'Warning'
  }

  if ($Strict -and ($BlacklistedCount -gt 0 -or $UnknownCount -gt 0)) {
    if ($BlacklistedCount -gt 0) { $eventId = 4902; $level = 'Error' }
    else                         { $eventId = 4901; $level = 'Warning' }
  }

  [pscustomobject]@{
    EventId = [int]$eventId
    Level   = [string]$level
  }
}

function New-SummaryLines {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][int]$Total,
    [Parameter(Mandatory=$true)][int]$Whitelisted,
    [Parameter(Mandatory=$true)][int]$Unknown,
    [Parameter(Mandatory=$true)][int]$Blacklisted,
    [Parameter(Mandatory=$true)]$Audit
  )

  $lines = @()
  $lines += ("Total={0}; Whitelisted={1}; Unknown={2}; Blacklisted={3}" -f $Total, $Whitelisted, $Unknown, $Blacklisted)

  if ($Blacklisted -gt 0) {
    $names = (@($Audit.Blacklisted) | Select-Object -ExpandProperty Name | Sort-Object)
    $lines += ("Blacklisted: " + ($names -join '; '))
  }
  if ($Unknown -gt 0) {
    $names = (@($Audit.Unknown) | Select-Object -ExpandProperty Name | Sort-Object)
    $lines += ("Unknown: " + ($names -join '; '))
  }

  return ,$lines
}

# -------------------- Console output (host only) --------------------
function Get-ColorForLevel {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$Level)

  switch ($Level) {
    'Error'   { 'Red' }
    'Warning' { 'Yellow' }
    default   { 'Green' }
  }
}

function Write-ConsoleBanner {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$Title,
    [ConsoleColor]$Color = 'Cyan'
  )
  Write-Host ""
  Write-Host ("=" * 62) -ForegroundColor $Color
  Write-Host $Title -ForegroundColor $Color
  Write-Host ("=" * 62) -ForegroundColor $Color
}

function Write-ConsoleKeyValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$Key,
    [Parameter(Mandatory=$true)][string]$Value,
    [ConsoleColor]$KeyColor = 'DarkGray',
    [ConsoleColor]$ValueColor = 'Gray'
  )
  Write-Host ("{0,-16}: " -f $Key) -NoNewline -ForegroundColor $KeyColor
  Write-Host $Value -ForegroundColor $ValueColor
}

function Write-ConsoleList {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$Header,
    [AllowEmptyCollection()][string[]]$Items,
    [ConsoleColor]$HeaderColor = 'Gray',
    [ConsoleColor]$ItemColor = 'Gray',
    [int]$MaxItems = 20
  )

  # Empty lists are valid: do nothing.
  if (-not $Items -or $Items.Count -eq 0) { return }

  Write-Host $Header -ForegroundColor $HeaderColor
  $take = [Math]::Min($Items.Count, $MaxItems)
  for ($i = 0; $i -lt $take; $i++) {
    Write-Host ("  - " + [string]$Items[$i]) -ForegroundColor $ItemColor
  }
  if ($Items.Count -gt $MaxItems) {
    Write-Host ("  ... ({0} more)" -f ($Items.Count - $MaxItems)) -ForegroundColor 'DarkGray'
  }
}

function Write-ConsoleSummary {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][pscustomobject]$ResultObject)

  $statusColor = Get-ColorForLevel -Level $ResultObject.Status.Level

  Write-ConsoleBanner -Title "Software Audit" -Color 'Cyan'
  Write-ConsoleKeyValue -Key 'Timestamp' -Value ([string]$ResultObject.Time)
  Write-ConsoleKeyValue -Key 'Host' -Value ([string]$ResultObject.Host)
  Write-ConsoleKeyValue -Key 'Catalog' -Value ([string]$ResultObject.Catalog.Meta.Source)
  Write-ConsoleKeyValue -Key 'EventSource' -Value ("{0} (ready={1})" -f $ResultObject.EventSource.Name, $ResultObject.EventSource.Ready)

  Write-Host ""
  Write-Host ("Status          : {0} ({1})" -f $ResultObject.Status.EventId, $ResultObject.Status.Level) -ForegroundColor $statusColor
  Write-Host ("Counts          : Total={0}  Whitelisted={1}  Unknown={2}  Blacklisted={3}" -f `
    $ResultObject.Total, $ResultObject.CountWhitelisted, $ResultObject.CountUnknown, $ResultObject.CountBlacklisted) -ForegroundColor 'Gray'

  Write-Host ""
  Write-Host "Summary:" -ForegroundColor 'Gray'
  foreach ($l in @($ResultObject.Summary)) {
    Write-Host ("  " + [string]$l) -ForegroundColor 'Gray'
  }

  $blNames = @($ResultObject.Blacklisted | Select-Object -ExpandProperty Name | Sort-Object)
  $ukNames = @($ResultObject.Unknown     | Select-Object -ExpandProperty Name | Sort-Object)

  Write-Host ""
  Write-ConsoleList -Header "Blacklisted items:" -Items $blNames -HeaderColor 'Red' -ItemColor 'Red' -MaxItems 20
  Write-ConsoleList -Header "Unknown items:"     -Items $ukNames -HeaderColor 'Yellow' -ItemColor 'Yellow' -MaxItems 20

  Write-Host ("=" * 62) -ForegroundColor 'Cyan'
  Write-Host ""
}

# -------------------- MAIN --------------------
$eventSourceReady = Ensure-EventSource

try {
  $catalog = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath
  $inv     = Get-InstalledSoftware
  $audit   = Test-SoftwareCompliance -Inventory $inv -Catalog $catalog

  $cntTotal = [int](@($inv).Count)
  $cntBL    = [int](@($audit.Blacklisted).Count)
  $cntWL    = [int](@($audit.Whitelisted).Count)
  $cntUK    = [int](@($audit.Unknown).Count)

  $status = Get-AuditStatus -BlacklistedCount $cntBL -UnknownCount $cntUK -Strict:$Strict
  $summaryLines = New-SummaryLines -Total $cntTotal -Whitelisted $cntWL -Unknown $cntUK -Blacklisted $cntBL -Audit $audit

  $result = [pscustomobject]@{
    Time             = (Get-Date).ToString('s')
    Host             = [string]$env:COMPUTERNAME
    Catalog          = $catalog
    EventSource      = [pscustomobject]@{ Name = [string]$Script:EventSourceName; Ready = [bool]$eventSourceReady }
    Status           = $status

    Total            = $cntTotal
    CountWhitelisted = $cntWL
    CountUnknown     = $cntUK
    CountBlacklisted = $cntBL

    Summary          = @($summaryLines)

    # Pipeline-friendly structured data
    Whitelisted      = @($audit.Whitelisted)
    Blacklisted      = @($audit.Blacklisted)
    Unknown          = @($audit.Unknown)
  }

  # Proof JSON (optional)
  if (-not [string]::IsNullOrWhiteSpace($StatePath)) {
    try {
      $dir = Split-Path -Parent $StatePath
      if ($dir) { Ensure-Directory -Path $dir | Out-Null }
      ($result | ConvertTo-Json -Depth 7) | Set-Content -Encoding UTF8 -LiteralPath $StatePath
    } catch {}
  }

  # Event (best effort)
  $msg = [string](@($summaryLines) -join "`r`n")
  Write-HealthEvent -Id $status.EventId -Msg $msg -Level $status.Level | Out-Null

  # Console summary (host output only)
  Write-ConsoleSummary -ResultObject $result

  # Pipeline output (structured object only)
  #$result

  if     ($status.EventId -eq 4902) { exit 2 }
  elseif ($status.EventId -eq 4901) { exit 1 }
  else                              { exit 0 }

} catch {
  $errMsg = [string]("SW Inventory Error: " + $_.Exception.Message)

  Write-HealthEvent -Id 4902 -Msg $errMsg -Level 'Error' | Out-Null

  Write-ConsoleBanner -Title "Software Audit (FAILED)" -Color 'Red'
  Write-Host ("Error: {0}" -f $errMsg) -ForegroundColor 'Red'

  if ($_.InvocationInfo) {
    Write-Host ("Line:    {0}" -f $_.InvocationInfo.ScriptLineNumber) -ForegroundColor 'DarkGray'
    Write-Host ("Cmd:     {0}" -f $_.InvocationInfo.Line.Trim()) -ForegroundColor 'DarkGray'
  }

  Write-Host ""
  exit 2
}
