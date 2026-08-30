#requires -version 5.1
<#
.SYNOPSIS
  Checks the local machine for missing security patches by comparing installed KBs against a curated JSON feed, then reports missing Critical and Zero-Day items.

.DESCRIPTION
  This script reads installed Windows hotfixes/KBs from the local system and compares them to a JSON “KB feed” (a curated list of required patches).
  It classifies missing items into:
  - MissingCriticalKBs: required/critical updates that are not installed.
  - MissingZeroDayKBs: required updates flagged as zero-day mitigations that are not installed.

  The script produces:
  - A grouped, colorized console report.
  - A structured report object (only when -PassThru is used) suitable for automation:
    Export-Csv, ConvertTo-Json, Where-Object, etc.
  - A JSON state file for auditing/monitoring.
  - An optional Application event log entry (if the event source is available).

  If the KB feed cannot be loaded (missing file, invalid JSON, empty feed, missing required properties), the script continues with a safe default feed
  (an empty KB list) and reports FeedStatus accordingly.

.PARAMETER KBFeedPath
  Path to the JSON KB feed file.
  If this path is empty or matches a legacy template-path pattern, the feed is treated as missing.

  The root object must contain a KBs array. Supported per-item properties:
  - KB        (required) String in the form "KB" + digits (e.g., KB5031234)
  - Title     (optional) Human readable text shown in the console output
  - IsZeroDay (optional) Boolean; when true the KB is counted as zero-day gap if missing
  - Severity  (optional) Free-form value preserved in the output

.PARAMETER StatePath
  Path to the JSON state file written by the script.
  If this path is empty or matches a legacy template-path pattern, the script uses a safe default under ProgramData.

  The state file contains the same structured information that can be emitted via -PassThru, plus execution metadata and status fields.

.PARAMETER Strict
  Escalation mode.
  When set, any of the following conditions is treated as an Error result:
  - Missing critical KBs
  - Missing zero-day KBs
  - Feed could not be loaded (missing/invalid/empty)

.PARAMETER PassThru
  Emits the final structured report object to the success output stream.
  Without -PassThru, the script writes no objects to the pipeline (console-only + state file + optional event log).

.PARAMETER UseInformationStream
  Changes how the console report is written.
  - Default: uses Write-UiLine (always visible; does not produce pipeline objects).
  - When set: uses Write-Information for console output (visibility depends on InformationPreference).


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER ConfigPath
  Path to JSON configuration file.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
  None by default.

  When -PassThru is specified:
  System.Management.Automation.PSCustomObject with these top-level properties:
  - Host
  - Time
  - User
  - KBFeedPath
  - FeedStatus
  - StatePath
  - StateStatus
  - Strict
  - InstalledKBs
  - CheckedFeedKBs
  - CheckedFeedKBCount
  - MissingCriticalKBs
  - MissingZeroDayKBs
  - Errors
  - EventId
  - EventLevel

.NOTES
  Event log behavior:
  The script attempts to write an entry into the Application log using a dedicated source name. If the source is not available or cannot be created,
  the script falls back to console-only output for the event message.

  Exit codes:
  0=OK, 2=WARN, 1=FAIL.

.EXAMPLE
  # Run with a real KB feed and write the state JSON.
  .\20-MissingPatch-Notification.ps1 -KBFeedPath $KBFeedPath -StatePath "C:\ProgramData\PatchReminder\update-reminder.json"

.EXAMPLE
  # Strict mode for monitoring: treat any missing patch OR feed issue as an Error-level condition.
  .\20-MissingPatch-Notification.ps1 -KBFeedPath $KBFeedPath -Strict

.EXAMPLE
  # Automation-friendly usage: get the structured report and export a flat view.
  $r = .\20-MissingPatch-Notification.ps1 -KBFeedPath $KBFeedPath -PassThru
  $r | Select-Object Host, Time, FeedStatus, CheckedFeedKBCount,
                    @{n='MissingCriticalCount';e={$_.MissingCriticalKBs.Count}},
                    @{n='MissingZeroDayCount';e={$_.MissingZeroDayKBs.Count}} |
       Export-Csv -NoTypeInformation -Path ".\patch-status.csv"

.EXAMPLE
  # Filter missing zero-day KBs in the pipeline (requires -PassThru).
  .\20-MissingPatch-Notification.ps1 -KBFeedPath $KBFeedPath -PassThru |
    Select-Object -ExpandProperty MissingZeroDayKBs |
    Where-Object { $_.KB -match '^KB\d+$' }
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$KBFeedPath,
  [string]$StatePath,
  [switch]$Strict,
  [switch]$PassThru,
  [switch]$UseInformationStream

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


$script:UseInformationStream = [bool]$UseInformationStream


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '20-MissingPatch-Notification.ps1' -BoundParameters $PSBoundParameters `
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
  $result = Get-V2ResultObject -ScriptName '20-MissingPatch-Notification.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$script:Findings = Get-FindingsList

# ----------------------------
# Helpers
# ----------------------------

function Get-Count {
  [CmdletBinding()]
  param($Value)
  @($Value).Count
}

function Test-UnusablePath {
  [CmdletBinding()]
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
  $p = $Path.Trim()
  if ($p -match '(?i)^PATH[/\\]TO[/\\]') { return $true }
  if ($p -match '^(?i)<.+>$') { return $true }
  return $false
}

function Get-DefaultStatePath {
  [CmdletBinding()]
  param()

  $base = [Environment]::GetFolderPath('CommonApplicationData')
  Join-Path -Path $base -ChildPath "PatchReminder\update-reminder.json"
}

# Ensure-DirectoryForFile imported from lib/Common.psm1

function Get-ConsoleLine {
  [CmdletBinding()]
  param([string]$Char = '-', [int]$Width = 78)
  ($Char * $Width)
}


# Save-JsonUtf8NoBom: replaced by canonical Save-Json from lib/Serialization.psm1

function Get-DefaultFeed {
  [CmdletBinding()]
  param()

  [pscustomobject]@{
    KBs  = @()
    Meta = [pscustomobject]@{
      Generated = (Get-Date).ToString('s')
      Note      = 'Default empty feed (JSON missing/invalid/empty).'
    }
  }
}

function Load-KBFeedSafe {
  [CmdletBinding()]
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
    return [pscustomobject]@{ Feed = (Get-DefaultFeed); Status = 'Missing'; Error = $null }
  }

  try {
    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) {
      return [pscustomobject]@{ Feed = (Get-DefaultFeed); Status = 'InvalidOrEmpty'; Error = 'Feed file is empty.' }
    }

    $obj = $raw | ConvertFrom-Json
    if ($null -eq $obj -or $null -eq $obj.KBs) {
      return [pscustomobject]@{ Feed = (Get-DefaultFeed); Status = 'InvalidOrEmpty'; Error = "Feed JSON missing 'KBs' property." }
    }

    return [pscustomobject]@{ Feed = $obj; Status = 'OK'; Error = $null }
  } catch {
    return [pscustomobject]@{ Feed = (Get-DefaultFeed); Status = 'InvalidOrEmpty'; Error = $_.Exception.Message }
  }
}

function Normalize-FeedKBs {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Feed)

  $items = @($Feed.KBs)
  if ((Get-Count $items) -eq 0) { return @() }

  $out = foreach ($i in $items) {
    $kbId = $null
    try { $kbId = $i.KB } catch { $kbId = $null }
    if ([string]::IsNullOrWhiteSpace($kbId)) { continue }

    $kbId = $kbId.Trim()
    if ($kbId -notmatch '^KB\d+$') { continue }

    $title = $null
    try { $title = $i.Title } catch { $title = $null }
    if ([string]::IsNullOrWhiteSpace([string]$title)) { $title = 'n/a' }

    $isZeroDay = $false
    try {
      if ($i.PSObject -and ($i.PSObject.Properties.Name -contains 'IsZeroDay')) {
        $isZeroDay = [bool]$i.IsZeroDay
      }
    } catch { $isZeroDay = $false }

    $severity = $null
    try {
      if ($i.PSObject -and ($i.PSObject.Properties.Name -contains 'Severity')) {
        $severity = $i.Severity
      }
    } catch { $severity = $null }

    [pscustomobject]@{
      KB        = $kbId
      Title     = $title
      IsZeroDay = $isZeroDay
      Severity  = $severity
    }
  }

  @($out | Sort-Object KB -Unique)
}

function Get-InstalledKBs {
  [CmdletBinding()]
  param()

  $hotfixes = Get-HotFix |
    Where-Object { $_.HotFixID -and $_.HotFixID -like 'KB*' } |
    Select-Object -Property HotFixID, Description, InstalledOn

  @(
    @($hotfixes) |
      ForEach-Object { $_.HotFixID } |
      Where-Object { $_ } |
      ForEach-Object { $_.ToString().Trim() } |
      Sort-Object -Unique
  )
}

function Get-UiStyleForLevel {
  [CmdletBinding()]
  param([ValidateSet('Information','Warning','Error')][string]$Level)

  switch ($Level) {
    'Information' { 'Ok' }
    'Warning'     { 'Warn' }
    'Error'       { 'Err' }
    default       { 'Default' }
  }
}

# ----------------------------
# Main
# ----------------------------

$eventSource = 'PatchReminder'
if (-not (Ensure-EventSource -Source $eventSource -Log 'Application')) {
  Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
}

$run = [ordered]@{
  Host        = $env:COMPUTERNAME
  Time        = (Get-Date).ToString('s')
  User        = $env:USERNAME
  KBFeedPath  = $KBFeedPath
  StatePath   = $StatePath
  Strict      = [bool]$Strict
  FeedStatus  = 'OK'
  StateStatus = 'OK'
  Errors      = @()
}

if (Test-UnusablePath -Path $StatePath) {
  $StatePath = Get-DefaultStatePath
  $run.StatePath = $StatePath
  $run.Errors += "StatePath was not usable. Using default: $StatePath"
}

if (Test-UnusablePath -Path $KBFeedPath) {
  $run.FeedStatus = 'Missing'
  $run.Errors += "KBFeedPath was not usable. Provide a readable JSON file with -KBFeedPath."
}

$installedKB = @()
try {
  $installedKB = Get-InstalledKBs
} catch {
  $installedKB = @()
  $run.Errors += ("Get-HotFix failed: " + $_.Exception.Message)
}

$feedLoad = Load-KBFeedSafe -Path $KBFeedPath
$kbfeed   = $feedLoad.Feed

if ($run.FeedStatus -eq 'OK' -and $feedLoad.Status -ne 'OK') {
  $run.FeedStatus = $feedLoad.Status
}
if (-not [string]::IsNullOrWhiteSpace([string]$feedLoad.Error)) {
  $run.Errors += ("KB feed issue: " + $feedLoad.Error)
}

$feedKBs = Normalize-FeedKBs -Feed $kbfeed

$missingCritical = @()
$zeroDays        = @()

foreach ($kb in @($feedKBs)) {
  if ($installedKB -notcontains $kb.KB) {
    if ($kb.IsZeroDay -eq $true) { $zeroDays += $kb }
    else { $missingCritical += $kb }
  }
}

foreach ($z in @($zeroDays)) {
  Add-Finding -FindingList $script:Findings -Code 'PATCH-MissingZeroDay' -Severity 'High' `
    -Message ("Missing zero-day KB: {0} [{1}]" -f $z.KB, $z.Title) `
    -Extra @{ KB = $z.KB; Title = $z.Title; IsZeroDay = $true }
}
foreach ($mc in @($missingCritical)) {
  Add-Finding -FindingList $script:Findings -Code 'PATCH-MissingCritical' -Severity 'Medium' `
    -Message ("Missing critical KB: {0} [{1}]" -f $mc.KB, $mc.Title) `
    -Extra @{ KB = $mc.KB; Title = $mc.Title; IsZeroDay = $false }
}
if ($run.FeedStatus -ne 'OK') {
  Add-Finding -FindingList $script:Findings -Code 'PATCH-FeedIssue' -Severity 'Low' `
    -Message ("KB feed status: {0}" -f $run.FeedStatus)
}

$status = 4904
$level  = 'Information'

if ((Get-Count $zeroDays) -gt 0) {
  $status = 4906
  $level  = 'Error'
} elseif ((Get-Count $missingCritical) -gt 0) {
  $status = 4905
  $level  = 'Warning'
} elseif ($run.FeedStatus -ne 'OK') {
  $status = 4905
  $level  = 'Warning'
}

if ($Strict -and ( ((Get-Count $zeroDays) -gt 0) -or ((Get-Count $missingCritical) -gt 0) -or ($run.FeedStatus -ne 'OK') -or ($run.StateStatus -ne 'OK') )) {
  $status = 4906
  $level  = 'Error'
}

$report = [pscustomobject]([ordered]@{
  Host               = $run.Host
  Time               = $run.Time
  User               = $run.User
  KBFeedPath         = $run.KBFeedPath
  FeedStatus         = $run.FeedStatus
  StatePath          = $run.StatePath
  StateStatus        = $run.StateStatus
  Strict             = $run.Strict
  InstalledKBs       = @($installedKB)
  CheckedFeedKBs     = @($feedKBs)
  CheckedFeedKBCount = (Get-Count $feedKBs)
  MissingCriticalKBs = @($missingCritical)
  MissingZeroDayKBs  = @($zeroDays)
  Errors             = @($run.Errors)
  EventId            = $status
  EventLevel         = $level
})

try {
  Save-Json -InputObject $report -Path $StatePath -Depth 12 -NoBom
} catch {
  $run.StateStatus = 'WriteFailed'
  $run.Errors += ("State write failed: " + $_.Exception.Message)

  $report = [pscustomobject]([ordered]@{
    Host               = $run.Host
    Time               = $run.Time
    User               = $run.User
    KBFeedPath         = $run.KBFeedPath
    FeedStatus         = $run.FeedStatus
    StatePath          = $run.StatePath
    StateStatus        = $run.StateStatus
    Strict             = $run.Strict
    InstalledKBs       = @($installedKB)
    CheckedFeedKBs     = @($feedKBs)
    CheckedFeedKBCount = (Get-Count $feedKBs)
    MissingCriticalKBs = @($missingCritical)
    MissingZeroDayKBs  = @($zeroDays)
    Errors             = @($run.Errors)
    EventId            = $status
    EventLevel         = $level
  })
}

$zList = (@($zeroDays) | ForEach-Object { $_.KB } | Sort-Object -Unique) -join ', '
$mList = (@($missingCritical) | ForEach-Object { $_.KB } | Sort-Object -Unique) -join ', '

$msg = "Patch Status: MissingCritical=$(Get-Count $missingCritical), ZeroDayGaps=$(Get-Count $zeroDays), Checked=$(Get-Count $feedKBs), FeedStatus=$($run.FeedStatus), StateStatus=$($run.StateStatus)"
if ((Get-Count $zeroDays) -gt 0) { $msg += " | ZERO-DAY: $zList" }
elseif ((Get-Count $missingCritical) -gt 0) { $msg += " | Missing: $mList" }

Write-HealthEvent -Id $status -Msg $msg -Level $level -Source $eventSource

# Formatted console output.
$headerLine = Get-ConsoleLine -Char '='
$line       = Get-ConsoleLine -Char '-'
$levelStyle = Get-UiStyleForLevel -Level $level

Write-UiLine -Message $headerLine -Style Dim
Write-UiLine -Message "Patch Reminder" -Style Title
Write-UiLine -Message $headerLine -Style Dim
Write-UiLine -Message $msg -Style $levelStyle

Write-UiLine -Message "" -Style Default
Write-UiLine -Message $line -Style Dim
Write-UiLine -Message "Summary" -Style Title
Write-UiLine -Message $line -Style Dim

Write-UiLine -Message ("Host:            " + $run.Host) -Style Info
Write-UiLine -Message ("User:            " + $run.User) -Style Info
Write-UiLine -Message ("Time:            " + $run.Time) -Style Info
Write-UiLine -Message ("Installed KBs:   " + (Get-Count $installedKB)) -Style Info
Write-UiLine -Message ("Feed KBs:        " + (Get-Count $feedKBs) + " (" + $run.FeedStatus + ")") -Style Info
Write-UiLine -Message ("Missing critical:" + (" " * 1) + (Get-Count $missingCritical)) -Style Warn
Write-UiLine -Message ("Missing zero-day:" + (" " * 2) + (Get-Count $zeroDays)) -Style Err
Write-UiLine -Message ("Event:           " + $status + " / " + $level) -Style $levelStyle
Write-UiLine -Message ("State file:      " + $StatePath) -Style Info

if ((Get-Count $run.Errors) -gt 0) {
  Write-UiLine -Message "" -Style Default
  Write-UiLine -Message $line -Style Dim
  Write-UiLine -Message "Warnings/Errors" -Style Title
  Write-UiLine -Message $line -Style Dim

  foreach ($e in @($run.Errors)) {
    Write-UiLine -Message ("- " + $e) -Style Warn
  }
}

Write-UiLine -Message "" -Style Default
Write-UiLine -Message $line -Style Dim
Write-UiLine -Message "Details" -Style Title
Write-UiLine -Message $line -Style Dim

if (((Get-Count $zeroDays) -gt 0) -or ((Get-Count $missingCritical) -gt 0)) {
  foreach ($z in @($zeroDays)) {
    Write-UiLine -Message ("ZERO-DAY: " + $z.KB + " [" + $z.Title + "]") -Style Err
  }
  foreach ($m in @($missingCritical)) {
    Write-UiLine -Message ("Missing:  " + $m.KB + " [" + $m.Title + "]") -Style Warn
  }
} else {
  Write-UiLine -Message "No critical/zero-day gaps found in the feed scope." -Style Ok
}

Write-UiLine -Message $headerLine -Style Dim

# V2 output contract
$resultToken = if ($report.Errors.Count -gt 0) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '20-MissingPatch-Notification.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $report -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
