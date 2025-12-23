<#
.SYNOPSIS
  Audits Windows Scheduled Tasks for health and security hygiene, optionally remediates issues, and produces evidence.

.DESCRIPTION
  This script performs a full inventory of Scheduled Tasks and evaluates them against a rule catalog (JSON) or built-in defaults.
  It focuses on two goals:
  1) Reliability: Ensure defined "critical" tasks exist and are enabled (optionally re-enable them).
  2) Security hygiene: Detect potentially risky tasks based on common persistence patterns (locations, command lines, privilege level, signature/publisher, triggers).

  Evidence and reporting:
  - Writes an evidence record to Windows Event Log (Application log, configurable source).
  - Writes an evidence JSON file ("proof") containing summary + findings.
  - Prints a human-friendly summary to the console with highlighted status.
  - Emits exactly one structured proof object to the pipeline (for automation/export).

  Catalog input sources (highest precedence first):
  - -CatalogPath: explicit catalog JSON.
  - -ConfigPath: config JSON that can contain TasksHygiene.CatalogPath.
  - Built-in defaults (safe baseline) if no JSON can be loaded.

.PARAMETER CatalogPath
  Path to a catalog JSON that defines the hygiene rules.
  If the file cannot be read or parsed, the script falls back to built-in defaults.

  Expected catalog fields (all optional; missing fields are filled with defaults):
  - CriticalTasks: Array of regex patterns matching FullPath (e.g. "\\Microsoft\\Windows\\...").
  - AllowTaskExact: Array of regex patterns for tasks that should be excluded from "risky" classification.
  - AllowActionPathPrefixes: Array of allowed executable path prefixes (string starts-with checks).
  - DenyActionPathRegex: Array of regex patterns for denied executable/working directory locations.
  - DenyCommandLineRegex: Array of regex patterns considered suspicious in command lines.
  - AllowPublisherOrgRegex: Array of regex patterns matched against certificate subject to allow trusted publishers.
  - PurgeUnapproved: Boolean; when true, risky tasks are quarantined (export XML + disable) but only if -Remediate is also set.
  - QuarantineDir: Directory used to store exported task XML during quarantine.
  - Proof.OutFile: Path to the evidence JSON file.

.PARAMETER Remediate
  Enables remediation actions.
  When set, the script may:
  - Enable critical tasks that are present but disabled.
  - Quarantine risky tasks (export XML + disable) only when the catalog property PurgeUnapproved is true.

  When not set, the script runs in audit-only mode (no changes are made).

.PARAMETER Strict
  Controls compliance interpretation.
  When set, any drift (missing critical tasks, disabled critical tasks, quarantine errors, or other detected issues) is treated as a failure state.
  When not set, drift is still reported, but the overall run is considered informational unless errors occurred.

.PARAMETER ConfigPath
  Path to a configuration JSON that may contain a nested property TasksHygiene.CatalogPath.
  This allows central configuration to point to the catalog JSON without passing -CatalogPath explicitly.
  If ConfigPath is missing/unreadable/invalid, the script falls back to defaults.

.INPUTS
  None. This script does not accept pipeline input.

.OUTPUTS
  System.Management.Automation.PSCustomObject

  The script returns exactly one "proof" object to the pipeline, suitable for:
  - ConvertTo-Json
  - Export-Csv (with prior flattening if needed)
  - Where-Object filtering

  Proof object shape (high-level):
  - Time, Hostname
  - Summary: TotalTasks, CriticalKnown, RiskyDetected, Remediate, PurgeEnabled, Strict, ProofOutFile, QuarantineDir, IsAdmin
  - Critical: array of critical task records (FullPath, Enabled, LastRun, NextRun)
  - Risky: array of risky task records (FullPath, reasons, action details, signature info, triggers, etc.)
  - Actions: array of remediation actions performed (strings)
  - Notes/Drift: informational and drift messages (strings)

.EXAMPLE
  PS> .\07-ScheduledTasks-Hygiene.ps1

  Runs an audit using built-in defaults (or configured JSON if available via ConfigPath).
  Writes event log + proof JSON, prints summary, returns a proof object to the pipeline.

.EXAMPLE
  PS> .\07-ScheduledTasks-Hygiene.ps1 -CatalogPath 'PATH/TO/JSON/tasks-catalog.json'

  Runs an audit using an explicit catalog JSON.

.EXAMPLE
  PS> .\07-ScheduledTasks-Hygiene.ps1 -Remediate

  Runs with remediation enabled:
  - Attempts to enable critical tasks that are disabled.
  - Quarantine occurs only if the loaded catalog sets PurgeUnapproved = true.

.EXAMPLE
  PS> .\07-ScheduledTasks-Hygiene.ps1 -Remediate -WhatIf

  Simulates remediation actions. Shows what would be changed without making any changes.

.EXAMPLE
  PS> $proof = .\07-ScheduledTasks-Hygiene.ps1
  PS> $proof.Risky | ConvertTo-Json -Depth 6

  Captures the proof object and inspects risky findings as JSON.

.EXAMPLE
  PS> .\07-ScheduledTasks-Hygiene.ps1 | ConvertTo-Json -Depth 8 | Out-File .\proof.json

  Uses the pipeline output to generate an additional JSON artifact (separate from the built-in proof file).

.NOTES
  Permissions:
  - Reading tasks generally works without elevation.
  - Remediation (enabling/disabling tasks, creating an event source, writing quarantine/proof files) may require administrative rights.

  Safety:
  - Quarantine exports a task's XML definition before disabling it, so it can be recreated if needed.
  - Review the catalog patterns carefully; overly broad deny/allow rules can create false positives/negatives.

  Observability:
  - Console output is intended for humans (colored status and sections).
  - Automation should consume the single returned proof object and/or the proof JSON file.

#>


[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
  [string]$CatalogPath,
  [switch]$Remediate,
  [switch]$Strict,
  [string]$ConfigPath = "PATH/TO/JSON/config.json"
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# =========================
# Defaults (anonymized)
# =========================
$DefaultEventSource    = 'TasksHygiene'
$DefaultQuarantineDir  = 'PATH/TO/QUARANTINE/tasks'
$DefaultProofOutFile   = 'PATH/TO/PROOF/E5-Tasks.json'

# =========================
# Console (pretty)
# =========================
function Write-UiLine {
  param([string]$Text = "", [ConsoleColor]$Color = [ConsoleColor]::Gray)
  Write-Host $Text -ForegroundColor $Color
}

function Write-UiHeader {
  param([string]$Title)
  Write-Host ""
  Write-Host ("=" * 44) -ForegroundColor DarkGray
  Write-Host ("  {0}" -f $Title) -ForegroundColor Cyan
  Write-Host ("=" * 44) -ForegroundColor DarkGray
}

function Write-UiKV {
  param(
    [string]$Key,
    [object]$Value,
    [ConsoleColor]$KeyColor = [ConsoleColor]::DarkGray,
    [ConsoleColor]$ValueColor = [ConsoleColor]::Gray
  )
  $v = ""
  try { $v = [string]$Value } catch { $v = "" }
  Write-Host ("{0,-12} {1}" -f ($Key + ":"), $v) -ForegroundColor $KeyColor -NoNewline
  Write-Host "" -ForegroundColor $ValueColor
}

function Write-UiStatus {
  param(
    [string]$Label,
    [ValidateSet('OK','WARN','FAIL','INFO')]$State,
    [string]$Text
  )
  $c = [ConsoleColor]::Gray
  if ($State -eq 'OK')   { $c = [ConsoleColor]::Green }
  if ($State -eq 'WARN') { $c = [ConsoleColor]::Yellow }
  if ($State -eq 'FAIL') { $c = [ConsoleColor]::Red }
  if ($State -eq 'INFO') { $c = [ConsoleColor]::Cyan }

  Write-Host ("[{0}] " -f $Label) -ForegroundColor $c -NoNewline
  Write-Host $Text -ForegroundColor Gray
}

# =========================
# Helpers
# =========================
function Ensure-EventSource {
  param([string]$Source, [string]$Log='Application')
  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
      New-EventLog -LogName $Log -Source $Source -ErrorAction SilentlyContinue
    }
  } catch { }
}

function Write-HealthEvent {
  param(
    [int]$Id,
    [string]$Msg,
    [ValidateSet('Information','Warning','Error')]$Level='Information',
    [string]$Source
  )
  try {
    Write-EventLog -LogName Application -Source $Source -EntryType $Level -EventId $Id -Message $Msg
  } catch {
    Write-Host "[$Level][$Id] $Msg"
  }
}

function Is-Admin {
  try {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Ensure-Dir {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Save-Json {
  param([object]$Obj,[string]$Path)
  Ensure-Dir (Split-Path -Parent $Path)
  ($Obj | ConvertTo-Json -Depth 25) | Out-File -Encoding UTF8 -FilePath $Path
}

function Try-LoadJsonFile {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  if (-not (Test-Path $Path)) { return $null }
  try {
    $raw = Get-Content -Raw -Path $Path -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json -ErrorAction Stop)
  } catch {
    return $null
  }
}

function Get-PropValue {
  param(
    [Parameter(Mandatory=$true)]$Object,
    [Parameter(Mandatory=$true)][string]$Name,
    $Default = $null
  )
  if ($null -eq $Object) { return $Default }
  try {
    if ($Object.PSObject -and $Object.PSObject.Properties -and $Object.PSObject.Properties.Match($Name).Count -gt 0) {
      return $Object.PSObject.Properties[$Name].Value
    }
  } catch { }
  return $Default
}

function Coalesce-String {
  param([object]$Value,[string]$Default)
  $s = $null
  try { $s = [string]$Value } catch { $s = $null }
  if ([string]::IsNullOrWhiteSpace($s)) { return $Default }
  return $s
}

function Normalize-TaskPath {
  param([string]$TaskPath)
  if ([string]::IsNullOrWhiteSpace($TaskPath)) { return "\" }
  if ($TaskPath[0] -ne '\') { $TaskPath = "\" + $TaskPath }
  if ($TaskPath[-1] -ne '\') { $TaskPath = $TaskPath + "\" }
  return $TaskPath
}

function Normalize-FullTaskPath {
  param([string]$TaskPath,[string]$TaskName)
  $tp = Normalize-TaskPath $TaskPath
  return ($tp + $TaskName)
}

function Expand-NormalizePath {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  $p2 = [Environment]::ExpandEnvironmentVariables($Path)
  if ($p2 -match '^[\\/](System32|SysWOW64)[\\/]' ) {
    $p2 = Join-Path $env:WINDIR ($p2.TrimStart('\','/'))
  }
  return $p2
}

function Match-AnyRegex {
  param([string]$Text,[object]$Patterns)
  if ([string]::IsNullOrWhiteSpace($Text) -or $null -eq $Patterns) { return $false }
  foreach($p in @($Patterns)) {
    if ($p -and ($Text -match [string]$p)) { return $true }
  }
  return $false
}

function StartsWithAny {
  param([string]$Text,[object]$Prefixes)
  if ([string]::IsNullOrWhiteSpace($Text) -or $null -eq $Prefixes) { return $false }
  foreach($p in @($Prefixes)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$p) -and $Text -like "$p*") { return $true }
  }
  return $false
}

# =========================
# Catalog (safe defaults)
# =========================
function New-DefaultCatalog {
  param([string]$QuarantineDir,[string]$ProofOutFile)

  return [pscustomobject]([ordered]@{
    CriticalTasks = @(
      "\\Microsoft\\Windows\\Windows Defender\\.*",
      "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start",
      "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
      "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup",
      "\\Microsoft\\Windows\\StorageSense\\.*",
      "\\Microsoft\\Windows\\Servicing\\StartComponentCleanup"
    )
    AllowTaskExact = @(
      "\\Company\\Managed\\.*"
    )
    AllowActionPathPrefixes = @(
      "C:\Windows\",
      "C:\Program Files\",
      "C:\Program Files (x86)\",
      "PATH/TO/SCRIPTS/"
    )
    DenyActionPathRegex = @(
      "(?i)\\Users\\[^\\]+\\AppData\\",
      "(?i)\\Users\\[^\\]+\\Downloads\\",
      "(?i)\\Windows\\Temp\\",
      "(?i)\\ProgramData\\Temp\\"
    )
    DenyCommandLineRegex = @(
      "(?i)\bpowershell(\.exe)?\b.*\b-enc(odedcommand)?\b",
      "(?i)\bcmd(\.exe)?\b.*\b/c\b.*(AppData\\|\\Users\\|\\Windows\\Temp\\|\\ProgramData\\Temp\\)"
    )
    AllowPublisherOrgRegex = @(
      "(?i)\bO=Microsoft Corporation\b",
      "(?i)\bO=Company\b"
    )
    PurgeUnapproved = $false
    QuarantineDir   = $QuarantineDir
    Proof           = [pscustomobject]([ordered]@{ OutFile = $ProofOutFile })
  })
}

function Normalize-Catalog {
  param([object]$cat,[object]$fallback)

  if ($null -eq $cat) { return $fallback }

  foreach($k in @('CriticalTasks','AllowTaskExact','AllowActionPathPrefixes','DenyActionPathRegex','DenyCommandLineRegex','AllowPublisherOrgRegex')) {
    if ($null -eq (Get-PropValue $cat $k $null)) {
      $cat | Add-Member -NotePropertyName $k -NotePropertyValue (Get-PropValue $fallback $k @()) -Force
    }
  }

  if ($null -eq (Get-PropValue $cat 'PurgeUnapproved' $null)) {
    $cat | Add-Member -NotePropertyName 'PurgeUnapproved' -NotePropertyValue $false -Force
  }

  if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $cat 'QuarantineDir' $null))) {
    $cat | Add-Member -NotePropertyName 'QuarantineDir' -NotePropertyValue (Get-PropValue $fallback 'QuarantineDir' $DefaultQuarantineDir) -Force
  }

  $proof = Get-PropValue $cat 'Proof' $null
  if ($null -eq $proof) {
    $cat | Add-Member -NotePropertyName 'Proof' -NotePropertyValue ([pscustomobject]([ordered]@{ OutFile = (Get-PropValue $fallback.Proof 'OutFile' $DefaultProofOutFile) })) -Force
  } else {
    $out = Get-PropValue $proof 'OutFile' $null
    if ([string]::IsNullOrWhiteSpace([string]$out)) {
      $proof | Add-Member -NotePropertyName 'OutFile' -NotePropertyValue (Get-PropValue $fallback.Proof 'OutFile' $DefaultProofOutFile) -Force
    }
  }

  return $cat
}

function Load-Catalog {
  param([string]$CatalogPath,[string]$ConfigPath,[object]$DefaultCatalog)

  $cat = Try-LoadJsonFile -Path $CatalogPath
  if ($cat) { return (Normalize-Catalog -cat $cat -fallback $DefaultCatalog) }

  $cfg = Try-LoadJsonFile -Path $ConfigPath
  $th  = $null
  if ($cfg) { $th = Get-PropValue $cfg 'TasksHygiene' $null }
  if ($th) {
    $p = Get-PropValue $th 'CatalogPath' $null
    if (-not [string]::IsNullOrWhiteSpace([string]$p)) {
      $cat = Try-LoadJsonFile -Path ([string]$p)
      if ($cat) { return (Normalize-Catalog -cat $cat -fallback $DefaultCatalog) }
    }
  }

  return (Normalize-Catalog -cat $null -fallback $DefaultCatalog)
}

# =========================
# Task inspection / actions
# =========================
function Export-TaskXmlObject {
  param([string]$TaskName,[string]$TaskPath)
  $TaskPath = Normalize-TaskPath $TaskPath
  try {
    # Export-ScheduledTask returns an XML string.
    $xml = Export-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
    return [xml]$xml
  } catch { return $null }
}

function Get-TaskActionsFromXml {
  param([xml]$Xml)

  $actions = @()
  if ($null -eq $Xml -or $null -eq $Xml.Task) { return $actions }

  $actNode = $Xml.Task.Actions
  if ($null -eq $actNode) { return $actions }

  # Exec is optional; other action types may exist.
  if (-not ($actNode.PSObject.Properties.Name -contains 'Exec')) { return $actions }

  foreach($a in @($actNode.Exec)) {
    if ($null -eq $a) { continue }

    $cmdRaw = $null; $argRaw = $null; $wdRaw = $null
    if ($a.PSObject.Properties.Name -contains 'Command') { $cmdRaw = [string]$a.Command }
    if ($a.PSObject.Properties.Name -contains 'Arguments') { $argRaw = [string]$a.Arguments }
    if ($a.PSObject.Properties.Name -contains 'WorkingDirectory') { $wdRaw = [string]$a.WorkingDirectory }

    $cmd = Expand-NormalizePath $cmdRaw
    $arg = $argRaw
    $wd  = Expand-NormalizePath $wdRaw

    $actions += [pscustomobject]([ordered]@{
      Command          = $cmd
      Arguments        = $arg
      WorkingDirectory = $wd
      CommandLine      = ((@($cmd,$arg) -join ' ').Trim())
      ActionType       = 'Exec'
    })
  }

  return $actions
}

function Get-TaskMetaFromXml {
  param([xml]$Xml)

  $meta = [pscustomobject]([ordered]@{
    Author        = $null
    PrincipalUser = $null
    RunLevel      = $null
    Hidden        = $false
    Triggers      = @()
  })

  if ($null -eq $Xml -or $null -eq $Xml.Task) { return $meta }

  try { $meta.Author = $Xml.Task.RegistrationInfo.Author } catch { $meta.Author = $null }

  if ($Xml.Task.Principals -and $Xml.Task.Principals.Principal) {
    try { $meta.PrincipalUser = $Xml.Task.Principals.Principal.UserId } catch { $meta.PrincipalUser = $null }
    try { $meta.RunLevel      = $Xml.Task.Principals.Principal.RunLevel } catch { $meta.RunLevel = $null }
  }

  $hiddenRaw = $null
  if ($Xml.Task.Settings) {
    try { $hiddenRaw = [string]$Xml.Task.Settings.Hidden } catch { $hiddenRaw = $null }
  }
  if (-not [string]::IsNullOrWhiteSpace($hiddenRaw)) {
    try { $meta.Hidden = [bool]::Parse($hiddenRaw) } catch { $meta.Hidden = $false }
  }

  if ($Xml.Task.Triggers -and $Xml.Task.Triggers.ChildNodes) {
    foreach($n in $Xml.Task.Triggers.ChildNodes) { $meta.Triggers += $n.Name }
  }

  $meta.Triggers = @($meta.Triggers)
  return $meta
}

function Get-TaskStateInfo {
  param([string]$TaskName,[string]$TaskPath)

  $TaskPath = Normalize-TaskPath $TaskPath

  $state = "Unknown"; $next = $null; $last = $null; $ltr = $null
  $enabled = $null

  $ti = $null
  try { $ti = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop } catch { $ti = $null }

  if ($ti) {
    try { if ($ti.State) { $state = $ti.State.ToString() } } catch { $state = "Unknown" }
    try { if ($ti.NextRunTime -and $ti.NextRunTime -gt (Get-Date "2000-01-01")) { $next = $ti.NextRunTime } } catch { $next = $null }
    try { if ($ti.LastRunTime -and $ti.LastRunTime -gt (Get-Date "2000-01-01")) { $last = $ti.LastRunTime } } catch { $last = $null }
    try { $ltr = $ti.LastTaskResult } catch { $ltr = $null }
  }

  if ($state -eq 'Disabled') { $enabled = $false }
  elseif ($state -in @('Ready','Running','Queued')) { $enabled = $true }

  return [pscustomobject]([ordered]@{
    State          = $state
    Enabled        = $enabled
    NextRunTime    = $next
    LastRunTime    = $last
    LastTaskResult = $ltr
  })
}

function Get-TaskInfo {
  param($Task)

  $taskName = [string](Get-PropValue -Object $Task -Name 'TaskName' -Default $null)
  $taskPath = Normalize-TaskPath ([string](Get-PropValue -Object $Task -Name 'TaskPath' -Default "\"))

  if ([string]::IsNullOrWhiteSpace($taskName)) {
    return [pscustomobject]([ordered]@{
      Name           = $null
      TaskPath       = $taskPath
      FullPath       = $null
      Enabled        = $null
      State          = "Unknown"
      NextRunTime    = $null
      LastRunTime    = $null
      LastTaskResult = $null
      Author         = $null
      PrincipalUser  = $null
      RunLevel       = $null
      Hidden         = $false
      Triggers       = @()
      Actions        = @()
    })
  }

  $xml     = Export-TaskXmlObject -TaskName $taskName -TaskPath $taskPath
  $actions = @(Get-TaskActionsFromXml -Xml $xml)
  $meta    = Get-TaskMetaFromXml -Xml $xml
  $si      = Get-TaskStateInfo -TaskName $taskName -TaskPath $taskPath

  return [pscustomobject]([ordered]@{
    Name           = $taskName
    TaskPath       = $taskPath
    FullPath       = Normalize-FullTaskPath -TaskPath $taskPath -TaskName $taskName
    Enabled        = $si.Enabled
    State          = $si.State
    NextRunTime    = $si.NextRunTime
    LastRunTime    = $si.LastRunTime
    LastTaskResult = $si.LastTaskResult
    Author         = $meta.Author
    PrincipalUser  = $meta.PrincipalUser
    RunLevel       = $meta.RunLevel
    Hidden         = $meta.Hidden
    Triggers       = @($meta.Triggers)
    Actions        = $actions
  })
}

function Get-PublisherInfo {
  param([string]$FilePath)
  if (-not $FilePath -or -not (Test-Path $FilePath)) {
    return [pscustomobject]([ordered]@{ Subject=$null; IsSigned=$false; IsValid=$false; Status=$null })
  }
  try {
    $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
    $subject = $null
    try { $subject = $sig.SignerCertificate.Subject } catch { $subject = $null }
    return [pscustomobject]([ordered]@{
      Subject  = $subject
      IsSigned = [bool]$sig.SignerCertificate
      IsValid  = ($sig.Status -eq 'Valid')
      Status   = [string]$sig.Status
    })
  } catch {
    return [pscustomobject]([ordered]@{ Subject=$null; IsSigned=$false; IsValid=$false; Status="Error" })
  }
}

function Enable-TaskIfPresent {
  param([string]$TaskName,[string]$TaskPath,[switch]$Remediate)

  $TaskPath = Normalize-TaskPath $TaskPath
  $full = "$TaskPath$TaskName"

  try {
    $t = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
    $tEnabledProp = Get-PropValue -Object $t -Name 'Enabled' -Default $null

    $isEnabled = $null
    if ($null -ne $tEnabledProp) {
      $isEnabled = [bool]$tEnabledProp
    } else {
      $s = [string](Get-PropValue -Object $t -Name 'State' -Default '')
      if ($s -eq 'Disabled') { $isEnabled = $false }
      elseif ($s) { $isEnabled = $true }
    }

    if ($isEnabled -eq $false) {
      if ($Remediate -and $PSCmdlet.ShouldProcess($full,"Enable-ScheduledTask")) {
        Enable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop | Out-Null
        return [pscustomobject]([ordered]@{ Ok=$true;  Message="Enabled $full" })
      }
      return [pscustomobject]([ordered]@{ Ok=$false; Message="$full disabled" })
    }

    return [pscustomobject]([ordered]@{ Ok=$true; Message=$null })
  } catch {
    return [pscustomobject]([ordered]@{ Ok=$false; Message="$full missing" })
  }
}

function Quarantine-Task {
  param([string]$TaskName,[string]$TaskPath,[string]$QuarantineDir,[switch]$Remediate)

  $TaskPath = Normalize-TaskPath $TaskPath
  $full = "$TaskPath$TaskName"

  if (-not $Remediate) {
    return [pscustomobject]([ordered]@{ Ok=$false; Actions=@(); Error="Remediation off" })
  }

  $act = New-Object System.Collections.Generic.List[string]

  try {
    Ensure-Dir $QuarantineDir
    $xmlObj = Export-TaskXmlObject -TaskName $TaskName -TaskPath $TaskPath

    if ($xmlObj) {
      $safeName = ($full.TrimStart('\') -replace '[\\/:*?"<>|]','_') + ".xml"
      $outPath  = Join-Path $QuarantineDir $safeName
      $utf8NoBom = New-Object System.Text.UTF8Encoding($false)

      if ($PSCmdlet.ShouldProcess($outPath,"Write quarantine XML")) {
        [System.IO.File]::WriteAllText($outPath, $xmlObj.OuterXml, $utf8NoBom)
      }
      $act.Add("Exported $full -> $outPath")
    } else {
      $act.Add("Export failed for $full (no XML)")
    }
  } catch {
    $act.Add("Export failed for ${TaskPath}${TaskName}: $($_.Exception.Message)")
  }

  try {
    if ($PSCmdlet.ShouldProcess($full,"Disable-ScheduledTask")) {
      Disable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop | Out-Null
    }
    $act.Add("Disabled $full")
  } catch {
    $act.Add("Disable failed for ${TaskPath}${TaskName}: $($_.Exception.Message)")
  }

  return [pscustomobject]([ordered]@{ Ok=$true; Actions=$act.ToArray(); Error=$null })
}

function Evaluate-TaskRisk {
  param([pscustomobject]$TaskInfo,[object]$Catalog)

  $risk = [pscustomobject]([ordered]@{
    IsCritical       = $false
    IsAllowed        = $false
    Risky            = $false
    Reasons          = @()
    ActionPath       = $null
    CommandLine      = $null
    WorkingDirectory = $null
    PublisherSubject = $null
    PublisherValid   = $null
    SignatureStatus  = $null
  })

  $full = [string]$TaskInfo.FullPath
  if (Match-AnyRegex $full (Get-PropValue $Catalog 'CriticalTasks' @()))  { $risk.IsCritical = $true }
  if (Match-AnyRegex $full (Get-PropValue $Catalog 'AllowTaskExact' @())) { $risk.IsAllowed  = $true }

  $exec = $null
  $actionsArr = @($TaskInfo.Actions)
  if ($actionsArr.Count -gt 0) { $exec = $actionsArr[0] }  # StrictMode-safe via @(...).Count

  $cmd = $null; $cl = $null; $wd = $null
  if ($exec) { $cmd = $exec.Command; $cl = $exec.CommandLine; $wd = $exec.WorkingDirectory }

  if ($cmd) {
    $risk.ActionPath       = $cmd
    $risk.CommandLine      = $cl
    $risk.WorkingDirectory = $wd

    $pub = Get-PublisherInfo -FilePath $cmd
    $risk.PublisherSubject = $pub.Subject
    $risk.PublisherValid   = $pub.IsValid
    $risk.SignatureStatus  = $pub.Status
  }

  $enabled = $TaskInfo.Enabled
  if ($null -eq $enabled) { if ($TaskInfo.State -and $TaskInfo.State -ne 'Disabled') { $enabled = $true } }

  if ($enabled -and $cmd) {
    if (Match-AnyRegex $cmd (Get-PropValue $Catalog 'DenyActionPathRegex' @())) {
      $risk.Risky = $true; $risk.Reasons += "ActionPath in denied location"
    }
    if ($wd -and (Match-AnyRegex $wd (Get-PropValue $Catalog 'DenyActionPathRegex' @()))) {
      $risk.Risky = $true; $risk.Reasons += "WorkingDirectory in denied location"
    }
    if (-not (StartsWithAny $cmd (Get-PropValue $Catalog 'AllowActionPathPrefixes' @()))) {
      $risk.Risky = $true; $risk.Reasons += "ActionPath not under allowed prefixes"
    }
  }

  if ($enabled -and $cl -and (Get-PropValue $Catalog 'DenyCommandLineRegex' $null)) {
    if (Match-AnyRegex $cl (Get-PropValue $Catalog 'DenyCommandLineRegex' @())) {
      $risk.Risky = $true; $risk.Reasons += "CommandLine matches denied patterns"
    }
  }

  if (($TaskInfo.RunLevel -match 'Highest') -and $cmd) {
    if (-not $risk.PublisherValid) {
      $risk.Risky = $true; $risk.Reasons += "HighestPrivileges with non-valid signature"
    } else {
      $approved = $false
      foreach($rx in @(Get-PropValue $Catalog 'AllowPublisherOrgRegex' @())) {
        if ($risk.PublisherSubject -and ($risk.PublisherSubject -match [string]$rx)) { $approved = $true; break }
      }
      if (-not $approved) { $risk.Risky = $true; $risk.Reasons += "HighestPrivileges with unapproved publisher"
      }
    }
  }

  if ($TaskInfo.Hidden -and (@($TaskInfo.Triggers) -contains 'LogonTrigger')) {
    $risk.Risky = $true; $risk.Reasons += "Hidden + LogonTrigger"
  }

  return $risk
}

# =========================
# Proof object (pipeline output)
# =========================
$Proof = [pscustomobject]([ordered]@{
  Time     = (Get-Date).ToString('s')
  Hostname = $env:COMPUTERNAME
  Summary  = [pscustomobject]([ordered]@{})
  Notes    = @()
  Critical = @()
  Risky    = @()
  Actions  = @()
  Drift    = @()
})

# =========================
# Main
# =========================
$EventSource = $DefaultEventSource
Ensure-EventSource -Source $EventSource

$ok = $true
$drifts  = New-Object System.Collections.Generic.List[string]
$changes = New-Object System.Collections.Generic.List[string]

$catalogFallback = New-DefaultCatalog -QuarantineDir $DefaultQuarantineDir -ProofOutFile $DefaultProofOutFile

try {
  $isAdmin = Is-Admin
  if (-not $isAdmin) {
    $Proof.Notes += "Not elevated - remediation may fail."
    if ($Strict) { $ok = $false }
  }

  $cat = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath -DefaultCatalog $catalogFallback
  $cat.QuarantineDir = Coalesce-String (Get-PropValue $cat 'QuarantineDir' $null) $DefaultQuarantineDir

  $proofObj = Get-PropValue $cat 'Proof' $null
  if ($null -eq $proofObj) {
    $cat | Add-Member -NotePropertyName 'Proof' -NotePropertyValue ([pscustomobject]([ordered]@{ OutFile = $DefaultProofOutFile })) -Force
    $proofObj = $cat.Proof
  }
  $proofObj.OutFile = Coalesce-String (Get-PropValue $proofObj 'OutFile' $null) $DefaultProofOutFile

  $all = @()
  try { $all = Get-ScheduledTask -ErrorAction Stop } catch { $all = @() }  # ScheduledTasks module

  $taskInfos = foreach($t in $all) { Get-TaskInfo -Task $t }

  # --- Ensure critical tasks ---
  $criticalRecords = New-Object System.Collections.Generic.List[object]
  foreach($pat in @($cat.CriticalTasks)) {
    $hits = @($taskInfos | Where-Object { $_.FullPath -match [string]$pat })
    if (@($hits).Count -eq 0) {
      $drifts.Add("Critical missing: $pat")
      $ok = $false
      continue
    }

    foreach($h in @($hits)) {
      $res = Enable-TaskIfPresent -TaskName $h.Name -TaskPath $h.TaskPath -Remediate:$Remediate
      if (-not $res.Ok -and $res.Message) { $ok = $false; $drifts.Add($res.Message) }
      elseif ($res.Message) { $changes.Add($res.Message); $Proof.Actions += $res.Message }

      $criticalRecords.Add([pscustomobject]([ordered]@{
        FullPath = $h.FullPath
        Enabled  = $h.Enabled
        LastRun  = $h.LastRunTime
        NextRun  = $h.NextRunTime
      }))
    }
  }
  $Proof.Critical = $criticalRecords.ToArray()

  # --- Risk scan and optional quarantine ---
  $riskyRecords = New-Object System.Collections.Generic.List[object]
  foreach($ti in @($taskInfos)) {
    $r = Evaluate-TaskRisk -TaskInfo $ti -Catalog $cat
    if ($r.IsCritical -or $r.IsAllowed) { continue }

    if ($r.Risky) {
      $entry = [pscustomobject]([ordered]@{
        FullPath         = $ti.FullPath
        Enabled          = $ti.Enabled
        RunLevel         = $ti.RunLevel
        Hidden           = $ti.Hidden
        Triggers         = $ti.Triggers
        ActionPath       = $r.ActionPath
        CommandLine      = $r.CommandLine
        WorkingDirectory = $r.WorkingDirectory
        PublisherSubject = $r.PublisherSubject
        SignedValid      = $r.PublisherValid
        SignatureStatus  = $r.SignatureStatus
        Reasons          = $r.Reasons
      })

      $riskyRecords.Add($entry)

      if ([bool]$cat.PurgeUnapproved) {
        $q = Quarantine-Task -TaskName $ti.Name -TaskPath $ti.TaskPath -QuarantineDir $cat.QuarantineDir -Remediate:$Remediate
        if ($q.Ok -and @($q.Actions).Count -gt 0) {
          foreach($a in @($q.Actions)) { $changes.Add($a); $Proof.Actions += $a }
        } elseif ($q.Error) {
          $ok = $false
          $drifts.Add($q.Error)
        }
      }
    }
  }
  $Proof.Risky = $riskyRecords.ToArray()

  $Proof.Summary = [pscustomobject]([ordered]@{
    TotalTasks    = @($taskInfos).Count
    CriticalKnown = @($Proof.Critical).Count
    RiskyDetected = @($Proof.Risky).Count
    PurgeEnabled  = [bool]$cat.PurgeUnapproved
    Remediate     = [bool]$Remediate
    Strict        = [bool]$Strict
    IsAdmin       = [bool]$isAdmin
    ProofOutFile  = $proofObj.OutFile
    QuarantineDir = $cat.QuarantineDir
  })

  Save-Json -Obj $Proof -Path $proofObj.OutFile
  $changes.Add("Proof JSON: $($proofObj.OutFile)")

  if (@($Proof.Notes).Count -gt 0) { foreach($n in @($Proof.Notes)) { $drifts.Add($n) } }

  $lines = New-Object System.Collections.Generic.List[string]
  if ($changes.Count -gt 0) { $lines.Add("Changed: " + (($changes | Select-Object -Unique) -join ' | ')) }
  if ($drifts.Count  -gt 0) { $lines.Add("Drift:   " + (($drifts  | Select-Object -Unique) -join ' | ')) }
  if ($lines.Count -eq 0)   { $lines.Add("Scheduled tasks compliant; critical enabled; no risky tasks found.") }

  $msg = ($lines -join "`r`n")

  $eventId = if ($ok -and -not $Strict) { 5040 } else { 5050 }
  $level   = if ($ok -and -not $Strict) { 'Information' } else { 'Warning' }

  Write-HealthEvent -Id $eventId -Msg $msg -Level $level -Source $EventSource

  # Pretty console output (no pipeline pollution)
  Write-UiHeader "Scheduled Tasks Hygiene Summary"

  Write-UiKV "Host"       $Proof.Hostname
  Write-UiKV "Time"       $Proof.Time
  Write-UiKV "Admin"      $Proof.Summary.IsAdmin
  Write-UiKV "Remediate"  $Proof.Summary.Remediate
  Write-UiKV "Purge"      $Proof.Summary.PurgeEnabled
  Write-UiKV "Strict"     $Proof.Summary.Strict

  Write-Host ""
  Write-UiKV "Tasks"      $Proof.Summary.TotalTasks
  Write-UiKV "Critical"   $Proof.Summary.CriticalKnown
  Write-UiKV "Risky"      $Proof.Summary.RiskyDetected

  Write-Host ""
  Write-UiKV "Proof JSON" $Proof.Summary.ProofOutFile
  Write-UiKV "Quarantine" $Proof.Summary.QuarantineDir

  Write-Host ""
  if ($ok -and -not $Strict) {
    Write-UiStatus -Label "OK"   -State OK   -Text "No drift detected (or Strict is off)."
  } elseif ($ok -and $Strict) {
    Write-UiStatus -Label "WARN" -State WARN -Text "Strict mode enabled; review drift messages below."
  } else {
    Write-UiStatus -Label "FAIL" -State FAIL -Text "Drift detected."
  }

  if ($changes.Count -gt 0) {
    Write-Host ""
    Write-UiLine "Changes:" DarkGray
    foreach($c in ($changes | Select-Object -Unique)) { Write-UiStatus -Label "CHG" -State INFO -Text $c }
  }

  if ($drifts.Count -gt 0) {
    Write-Host ""
    Write-UiLine "Drifts:" DarkGray
    foreach($d in ($drifts | Select-Object -Unique)) { Write-UiStatus -Label "DRF" -State WARN -Text $d }
  }

  Write-Host ""
  Write-Host ("-" * 44) -ForegroundColor DarkGray

  # Pipeline-safe structured output (single object)
  #$Proof
}
catch {
  $errMsg = "Tasks hygiene error: " + $_.Exception.Message
  Write-HealthEvent -Id 5050 -Msg $errMsg -Level 'Error' -Source $EventSource

  Write-UiHeader "Scheduled Tasks Hygiene Summary"
  Write-UiStatus -Label "FAIL" -State FAIL -Text $errMsg

  throw
}
