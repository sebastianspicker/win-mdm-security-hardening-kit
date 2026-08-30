#requires -version 5.1
<#
.SYNOPSIS
Fast event log triage (Windows PowerShell 5.1) using Get-WinEvent -FilterHashtable.

.DESCRIPTION
Best-practice layout:
- Success output stream: structured objects only (safe for Export-Csv / ConvertTo-Json / Where-Object).
- Console output: blocks, separators, and colors use Write-UiLine / Write-Information only.

Features:
- Optional JSON config overrides loaded from $ConfigPath. Falls back to defaults if missing or invalid.
- Optional record de-duplication (true duplicates only).
- Optional "collapse" summary: groups similar events without removing records.
- Optional CSV export.

.PARAMETER ConfigPath
Optional path to JSON config supplied with $ConfigPath. If unreadable or invalid, defaults apply.

.PARAMETER Quiet
Suppresses console output (still returns objects).

.PARAMETER NoColor
Disables colored console output (still prints text).

.PARAMETER Collapse
Builds "similar event" groups for the summary (does not remove records).

.PARAMETER CollapseTop
Number of top similar groups shown in the summary.

.PARAMETER Deduplicate
Removes true duplicates from output (default: disabled). Uses RecordId when available.

.PARAMETER NormalizeMessage
If enabled, produces NormalizedMessage (single-line) and uses it for collapse grouping & CSV export.

.PARAMETER ExportPath
Optional CSV export path.

.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER PassThru
  Emit structured v2 result object to pipeline.

.PARAMETER Strict
  Treat warnings as failures.


.OUTPUTS
  None by default.
  When -PassThru is used, emits a PSCustomObject v2 result with Script, Mode, Result, Findings, Summary, and Metadata properties.

.EXAMPLE
  .\26-Get-WinEvent-FastTriage.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter()]
  [string]$ConfigPath,

  [Parameter()]
  [switch]$Quiet,

  [Parameter()]
  [switch]$NoColor,

  [Parameter()]
  [bool]$Collapse = $true,

  [Parameter()]
  [ValidateRange(1, 50)]
  [int]$CollapseTop = 5,

  [Parameter()]
  [bool]$Deduplicate = $false,

  [Parameter()]
  [bool]$NormalizeMessage = $true,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$LogName = 'System',

  [Parameter()]
  [ValidateRange(1, 24*365)]
  [int]$HoursBack = 6,

  [Parameter()]
  [ValidateSet(1,2,3,4,5)]
  [int[]]$Level = @(2,3),

  [Parameter()]
  [string[]]$ProviderName,

  [Parameter()]
  [int[]]$Id,

  [Parameter()]
  [ValidateRange(1, 1000000)]
  [int]$MaxEvents = 500,

  [Parameter()]
  [string]$ExportPath

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1')


$script:Quiet = [bool]$Quiet
$script:NoColor = [bool]$NoColor


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '26-Get-WinEvent-FastTriage.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '26-Get-WinEvent-FastTriage.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# -------------------------
# Console helpers (no pipeline pollution)
# -------------------------



function Get-LevelColor {
  [CmdletBinding()]
  param([AllowNull()][string]$LevelDisplayName)

  switch ($LevelDisplayName) {
    'Critical'     { 'Magenta' }
    'Error'        { 'Red' }
    'Warning'      { 'Yellow' }
    'Information'  { 'Gray' }
    'Verbose'      { 'DarkGray' }
    default        { 'Gray' }
  }
}

# -------------------------
# Config loading (optional) with safe defaults
# -------------------------
function Resolve-TriageConfig {
  [CmdletBinding()]
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

  if (-not (Test-Path -LiteralPath $Path)) {
    Write-Info ("Config not found: {0}. Using defaults." -f $Path)
    return $null
  }

  try {
    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json -ErrorAction Stop)
  }
  catch {
    Write-Info ("Config invalid/unreadable: {0}. Using defaults." -f $Path)
    Write-Info ("Config error: {0}" -f $_.Exception.Message)
    return $null
  }
}

function Apply-ConfigOverrides {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][pscustomobject]$Config)

  if ($null -ne $Config.LogName -and -not [string]::IsNullOrWhiteSpace([string]$Config.LogName)) {
    $script:LogName = [string]$Config.LogName
  }

  if ($null -ne $Config.HoursBack) {
    $hb = 0
    if ([int]::TryParse([string]$Config.HoursBack, [ref]$hb) -and $hb -ge 1 -and $hb -le (24*365)) {
      $script:HoursBack = $hb
    }
  }

  if ($null -ne $Config.Level) {
    $levels = @()
    foreach ($l in @($Config.Level)) {
      $parsed = $null
      if ([int]::TryParse([string]$l, [ref]$parsed) -and $parsed -in 1,2,3,4,5) {
        $levels += $parsed
      }
    }
    if ($levels.Count -gt 0) { $script:Level = $levels }
  }

  if ($null -ne $Config.ProviderName) {
    $p = @()
    foreach ($x in @($Config.ProviderName)) {
      if (-not [string]::IsNullOrWhiteSpace([string]$x)) { $p += [string]$x }
    }
    if ($p.Count -gt 0) { $script:ProviderName = $p }
  }

  if ($null -ne $Config.Id) {
    $ids = @()
    foreach ($x in @($Config.Id)) {
      $parsed = $null
      if ([int]::TryParse([string]$x, [ref]$parsed) -and $parsed -gt 0) { $ids += $parsed }
    }
    if ($ids.Count -gt 0) { $script:Id = $ids }
  }

  if ($null -ne $Config.MaxEvents) {
    $m = 0
    if ([int]::TryParse([string]$Config.MaxEvents, [ref]$m) -and $m -ge 1 -and $m -le 1000000) {
      $script:MaxEvents = $m
    }
  }

  if ($null -ne $Config.ExportPath -and -not [string]::IsNullOrWhiteSpace([string]$Config.ExportPath)) {
    Write-Info 'Ignoring config ExportPath; provide the output location explicitly with -ExportPath.'
  }

  if ($null -ne $Config.Deduplicate) {
    $d = $null
    if ([bool]::TryParse([string]$Config.Deduplicate, [ref]$d)) { $script:Deduplicate = $d }
  }

  if ($null -ne $Config.Collapse) {
    $c = $null
    if ([bool]::TryParse([string]$Config.Collapse, [ref]$c)) { $script:Collapse = $c }
  }

  if ($null -ne $Config.CollapseTop) {
    $ct = 0
    if ([int]::TryParse([string]$Config.CollapseTop, [ref]$ct) -and $ct -ge 1 -and $ct -le 50) {
      $script:CollapseTop = $ct
    }
  }

  if ($null -ne $Config.NormalizeMessage) {
    $nm = $null
    if ([bool]::TryParse([string]$Config.NormalizeMessage, [ref]$nm)) { $script:NormalizeMessage = $nm }
  }

  if ($null -ne $Config.Quiet) {
    $q = $null
    if ([bool]::TryParse([string]$Config.Quiet, [ref]$q)) { $script:Quiet = $q }
  }

  if ($null -ne $Config.NoColor) {
    $nc = $null
    if ([bool]::TryParse([string]$Config.NoColor, [ref]$nc)) { $script:NoColor = $nc }
  }
}

# -------------------------
# Data helpers
# -------------------------
function Normalize-Message {
  [CmdletBinding()]
  param([AllowNull()][string]$Message)

  if ($null -eq $Message) { return '' }
  $m = ($Message -replace "(`r`n|`n|`r)", ' ')
  $m = ($m -replace '\s{2,}', ' ').Trim()
  return $m
}

function Get-EventDedupeKey {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)]$Event)

  if ($null -ne $Event.RecordId) { return ("{0}|{1}" -f $Event.LogName, $Event.RecordId) }

  $tc = $Event.TimeCreated
  $msg = Normalize-Message -Message ([string]$Event.Message)
  return ("{0}|{1:o}|{2}|{3}|{4}" -f $Event.LogName, $tc, $Event.Id, $Event.ProviderName, $msg)
}

function Get-CollapseKey {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)]$Event)

  $sep = [char]0x1F
  $msg = if ($script:NormalizeMessage) { $Event.NormalizedMessage } else { Normalize-Message -Message ([string]$Event.Message) }
  return ("{0}{4}{1}{4}{2}{4}{3}" -f $Event.ProviderName, $Event.Id, $Event.LevelDisplayName, $msg, $sep)
}

# -------------------------
# Load config and apply defaults
# -------------------------
$config = Resolve-TriageConfig -Path $ConfigPath
if ($null -ne $config) { Apply-ConfigOverrides -Config $config }

if ($HoursBack -lt 1)  { $HoursBack = 6 }
if ($MaxEvents -lt 1)  { $MaxEvents = 500 }
if (-not $Level -or $Level.Count -eq 0) { $Level = @(2,3) }
if ($CollapseTop -lt 1) { $CollapseTop = 5 }

$startTime = (Get-Date).AddHours(-$HoursBack)

# -------------------------
# Query
# -------------------------
$filter = @{
  LogName   = $LogName
  StartTime = $startTime
  Level     = $Level
}
if ($ProviderName -and $ProviderName.Count -gt 0) { $filter.ProviderName = $ProviderName }
if ($Id -and $Id.Count -gt 0)                     { $filter.ID          = $Id }

$eventsRaw = @()
try {
  $eventsRaw = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
}
catch {
  if ($_.Exception.Message -match 'No events were found') {
    $eventsRaw = @()
  } else {
    Write-Warning "Get-WinEvent query failed: $($_.Exception.Message)"
    $v2Result = Get-V2ResultObject -ScriptName '26-Get-WinEvent-FastTriage.ps1' -Mode $Mode -Result 'FAIL' -Findings @() -Summary @{ Error = $_.Exception.Message } -Metadata @{}
    Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
    if ($PassThru) { $v2Result }
    exit (Get-V2ExitCode -Result 'FAIL')
  }
}

$events = @(foreach ($e in $eventsRaw) {
  $msg = $null
  try { $msg = $e.Message } catch { $msg = $null }

  $norm = if ($NormalizeMessage) { Normalize-Message -Message ([string]$msg) } else { $null }

  [pscustomobject]@{
    TimeCreated       = $e.TimeCreated
    LevelDisplayName  = $e.LevelDisplayName
    Id                = $e.Id
    ProviderName      = $e.ProviderName
    LogName           = $LogName
    RecordId          = $e.RecordId
    Message           = $msg
    NormalizedMessage = $norm
  }
})

$dedupRemoved = 0
if ($Deduplicate -and $events.Count -gt 1) {
  $seen = New-Object 'System.Collections.Generic.HashSet[string]'
  $tmp = New-Object 'System.Collections.Generic.List[object]'
  foreach ($ev in $events) {
    $k = Get-EventDedupeKey -Event $ev
    if ($seen.Add($k)) { [void]$tmp.Add($ev) }
  }
  $dedupRemoved = ($events.Count - $tmp.Count)
  $events = $tmp.ToArray()
}

$exported = $false
$exportError = $null
if ($ExportPath) {
  try {
    if ($NormalizeMessage) {
      Save-Csv -InputObject @($events |
        Select-Object TimeCreated, LevelDisplayName, Id, ProviderName, LogName, RecordId, NormalizedMessage) -Path $ExportPath
    } else {
      Save-Csv -InputObject @($events |
        Select-Object TimeCreated, LevelDisplayName, Id, ProviderName, LogName, RecordId, Message) -Path $ExportPath
    }

    $exported = $true
  }
  catch {
    $exportError = $_.Exception.Message
    Write-Warning ("CSV export failed for '{0}'. Error: {1}" -f $ExportPath, $exportError)
  }
}

# -------------------------
# Summary (console only)
# -------------------------
$minTime = $null
$maxTime = $null
$levelStats = @()
$providerStats = @()
$idStats = @()
$collapseSummary = @()

if ($events.Count -gt 0) {
  $minTime = ($events | Measure-Object -Property TimeCreated -Minimum).Minimum
  $maxTime = ($events | Measure-Object -Property TimeCreated -Maximum).Maximum

  $levelStats = @($events | Group-Object -Property LevelDisplayName | Sort-Object Count -Descending)
  $providerStats = @($events | Group-Object -Property ProviderName | Sort-Object Count -Descending | Select-Object -First 5)
  $idStats = @($events | Group-Object -Property Id | Sort-Object Count -Descending | Select-Object -First 5)

  if ($Collapse) {
    $collapseSummary = @(
      $events |
      Group-Object -Property { Get-CollapseKey -Event $_ } |
      Sort-Object Count -Descending |
      Select-Object -First $CollapseTop |
      ForEach-Object {
        $sample = $_.Group[0]
        $times = $_.Group | Select-Object -ExpandProperty TimeCreated
        [pscustomobject]@{
          Count     = $_.Count
          Provider  = $sample.ProviderName
          Id        = $sample.Id
          Level     = $sample.LevelDisplayName
          FirstSeen = ($times | Measure-Object -Minimum).Minimum
          LastSeen  = ($times | Measure-Object -Maximum).Maximum
        }
      }
    )
  }
}

if (-not $Quiet) {
  Write-Section "Eventlog Triage Summary"

  Write-UiLine ("LogName      : {0}" -f $LogName) -ForegroundColor White
  Write-UiLine ("HoursBack    : {0}" -f $HoursBack) -ForegroundColor White
  Write-UiLine ("StartTime    : {0}" -f $startTime) -ForegroundColor White
  Write-UiLine ("Level(s)     : {0}" -f ($Level -join ', ')) -ForegroundColor White
  Write-UiLine ("ProviderName : {0}" -f ($(if ($ProviderName -and $ProviderName.Count -gt 0) { $ProviderName -join ', ' } else { '<none>' }))) -ForegroundColor White
  Write-UiLine ("Id(s)        : {0}" -f ($(if ($Id -and $Id.Count -gt 0) { $Id -join ', ' } else { '<none>' }))) -ForegroundColor White
  Write-UiLine ("MaxEvents    : {0}" -f $MaxEvents) -ForegroundColor White
  Write-UiLine ("Returned     : {0}" -f $events.Count) -ForegroundColor White

  if ($events.Count -gt 0) {
    Write-UiLine ("TimeRange    : {0} .. {1}" -f $minTime, $maxTime) -ForegroundColor White
  } else {
    Write-UiLine ("TimeRange    : <n/a>") -ForegroundColor DarkGray
  }

  Write-UiLine ("Deduplicate  : {0} (removed: {1})" -f $Deduplicate, $dedupRemoved) -ForegroundColor DarkGray
  Write-UiLine ("Collapse     : {0} (top: {1})" -f $Collapse, $CollapseTop) -ForegroundColor DarkGray
  Write-UiLine ("ExportPath   : {0}" -f ($(if ($ExportPath) { $ExportPath } else { '<none>' }))) -ForegroundColor DarkGray
  Write-UiLine ("Exported     : {0}" -f $exported) -ForegroundColor DarkGray

  Write-Info ""  # blank line (safe now)

  if ($levelStats.Count -gt 0) {
    Write-UiLine "Levels:" -ForegroundColor Cyan
    foreach ($g in $levelStats) {
      $c = Get-LevelColor -LevelDisplayName $g.Name
      Write-UiLine ("  {0,-12} {1,6}" -f $g.Name, $g.Count) -ForegroundColor $c
    }
  }

  if ($providerStats.Count -gt 0) {
    Write-Info ""
    Write-UiLine "Top Providers:" -ForegroundColor Cyan
    foreach ($g in $providerStats) {
      Write-UiLine ("  {0,-40} {1,6}" -f $g.Name, $g.Count) -ForegroundColor Gray
    }
  }

  if ($idStats.Count -gt 0) {
    Write-Info ""
    Write-UiLine "Top Event IDs:" -ForegroundColor Cyan
    foreach ($g in $idStats) {
      Write-UiLine ("  {0,-10} {1,6}" -f $g.Name, $g.Count) -ForegroundColor Gray
    }
  }

  if ($collapseSummary.Count -gt 0) {
    Write-Info ""
    Write-UiLine "Top Similar (collapsed):" -ForegroundColor Cyan
    foreach ($row in $collapseSummary) {
      $c = Get-LevelColor -LevelDisplayName $row.Level
      Write-UiLine ("  {0,6}x  {1}/{2}/{3}   {4} .. {5}" -f $row.Count, $row.Provider, $row.Id, $row.Level, $row.FirstSeen, $row.LastSeen) -ForegroundColor $c
    }
  }

  Write-UiLine ('-' * 70) -ForegroundColor DarkGray
}

# V2 output contract
$exportRequested = -not [string]::IsNullOrWhiteSpace($ExportPath)
$findings = @()
if ($exportRequested -and -not $exported) {
  $findings += [pscustomobject]@{
    Code     = 'EVT-ExportFailed'
    Severity = 'Medium'
    Message  = ("Requested CSV export failed for '{0}': {1}" -f $ExportPath, $exportError)
  }
}
$resultToken = if ($findings.Count -gt 0) { 'WARN' } else { 'OK' }
if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
$summary = [pscustomobject]@{
  ComputerName    = $env:COMPUTERNAME
  Timestamp       = Get-Date
  EventsReturned  = @($events).Count
  ExportRequested = $exportRequested
  ExportPath      = $(if ($exportRequested) { $ExportPath } else { $null })
  Exported        = $exported
  ExportError     = $exportError
}
$v2Result = Get-V2ResultObject -ScriptName '26-Get-WinEvent-FastTriage.ps1' -Mode $Mode -Result $resultToken -Findings $findings -Summary $summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
