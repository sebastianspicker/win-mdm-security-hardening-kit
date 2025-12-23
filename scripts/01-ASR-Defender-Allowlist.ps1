<#
.SYNOPSIS
  Synchronizes Microsoft Defender Antivirus exclusions, Attack Surface Reduction (ASR) Only Exclusions, and Controlled Folder Access (CFA) allowlists from a JSON definition.

.DESCRIPTION
  This script enforces a desired allowlist state for Microsoft Defender-related settings by comparing the local configuration with a JSON definition and then:
  - Reporting drift (differences) without changing the system (default behavior).
  - Optionally remediating drift by adding/removing entries to match the desired state.

  The script is designed to be:
  - Safe and idempotent: running it multiple times results in the same final configuration.
  - Defensive: risky allowlist entries (for example wildcards, UNC paths, device paths, or overly broad system paths) are rejected and reported.
  - Auditable: a structured result object can be emitted to the pipeline, and an audit JSON file can be written to disk.
  - Operator-friendly: a human-readable console summary is printed at the end.

  Data sources:
  - Desired state: JSON allowlist file (primary) or a baseline mode (fallback).
  - Current state: local Defender preferences retrieved at runtime.

.PARAMETER Remediate
  If specified, applies the calculated diff to the local system.
  If omitted, the script runs in audit-only mode and performs no changes.

.PARAMETER ConfigPath
  Path to an optional configuration JSON file that can contain the path to the allowlist JSON.
  This is a convenience input for centralized deployments.

.PARAMETER ExceptionsPath
  Path to the allowlist JSON file that defines the desired state.
  If provided, it takes precedence over any path discovered via -ConfigPath.

.PARAMETER AuditPath
  Path to a JSON file that will receive an audit record of the run.
  If the directory does not exist, it is created.

.PARAMETER Passthru
  If specified, outputs exactly one structured object to the pipeline containing:
  - Metadata about the run (time, computer, mode, JSON source)
  - Per-category diffs (current/desired/add/remove/rejected)
  - Remediation results and errors (if remediation was requested)

  If omitted, nothing is written to the pipeline (console output only).

.PARAMETER StrictJson
  If specified, the script fails if the allowlist JSON cannot be loaded or parsed.
  If omitted, the script falls back to the selected -BaselineMode.

.PARAMETER BaselineMode
  Determines the fallback behavior when the allowlist JSON is missing, empty, or invalid (and -StrictJson is not set):
  - Current : Desired state is set to the current local configuration (no drift, no changes).
  - Minimum : Desired state is set to a minimal baseline intended to avoid broad exclusions by default.

  The baseline mode used is shown in the console summary and included in the structured output.

.OUTPUTS
  None by default.

  When -Passthru is used:
  - A single PSCustomObject with properties such as:
    Timestamp, ComputerName, Remediate, SourceJson, AuditPath,
    JsonLoaded, JsonError, BaselineUsed, Notes,
    TotalAdd, TotalRemove, TotalRejected, TotalErrors, Result,
    Diffs, Results, ErrorsFlat, PerCategory

.INPUTS
  None. This script does not accept pipeline input.

.EXAMPLE
  # Audit-only: show drift (no changes applied)
  .\Defender-Allowlist-Sync.ps1 -ExceptionsPath "PATH/TO/JSON"

.EXAMPLE
  # Remediate: apply the diff to match the JSON allowlist
  .\Defender-Allowlist-Sync.ps1 -ExceptionsPath "PATH/TO/JSON" -Remediate

.EXAMPLE
  # Use a config file that contains the allowlist path (ExceptionsPath not specified)
  .\Defender-Allowlist-Sync.ps1 -ConfigPath "PATH/TO/CONFIG.json"

.EXAMPLE
  # Enforce strict JSON loading (fail if JSON is missing/invalid)
  .\Defender-Allowlist-Sync.ps1 -ExceptionsPath "PATH/TO/JSON" -StrictJson

.EXAMPLE
  # Emit structured output for reporting
  .\Defender-Allowlist-Sync.ps1 -ExceptionsPath "PATH/TO/JSON" -Passthru | ConvertTo-Json -Depth 6

.EXAMPLE
  # Emit structured output and export a compact report
  .\Defender-Allowlist-Sync.ps1 -ExceptionsPath "PATH/TO/JSON" -Passthru |
    Select-Object Timestamp,ComputerName,Result,TotalAdd,TotalRemove,TotalRejected,TotalErrors,SourceJson |
    Export-Csv -NoTypeInformation -Path "PATH/TO/REPORT.csv"

.NOTES
  Safety and behavior notes:
  - Entries flagged as risky are excluded from remediation and counted as Rejected.
  - In audit-only mode the script reports drift but performs no system changes.
  - A console summary is always printed; it is intended for humans and is not written to the pipeline.
  - The pipeline output (when enabled) is always a single structured object to support downstream automation.

  Operational considerations:
  - Changing Defender/ASR/CFA settings typically requires elevated permissions.
  - Tamper protection or organizational policy may prevent changes; such failures are captured in the results/errors.
#>


[CmdletBinding()]
param(
  [switch]$Remediate,

  # Generic placeholders for GitHub
  [string]$ConfigPath = "PATH/TO/CONFIG.json",
  [string]$ExceptionsPath,
  [string]$AuditPath  = "PATH/TO/AUDIT.json",

  [switch]$Passthru,
  [switch]$StrictJson,

  [ValidateSet('Current','Minimum')]
  [string]$BaselineMode = 'Minimum'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ----------------------------- Helpers --------------------------------------------

function New-DefaultDesiredConfig {
  [CmdletBinding()]
  param()

  [pscustomobject]@{
    Defender = [pscustomobject]@{
      ExclusionPaths      = @()
      ExclusionProcesses  = @()
      ExclusionExtensions = @()
    }
    ASR = [pscustomobject]@{
      OnlyExclusions = @()
    }
    CFA = [pscustomobject]@{
      AllowedApplications = @()
      ProtectedFolders    = @()
    }
  }
}

function New-NullSafeDesiredFromCurrent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$Preference
  )

  [pscustomobject]@{
    Defender = [pscustomobject]@{
      ExclusionPaths      = @($Preference.ExclusionPath)
      ExclusionProcesses  = @($Preference.ExclusionProcess)
      ExclusionExtensions = @($Preference.ExclusionExtension)
    }
    ASR = [pscustomobject]@{
      OnlyExclusions = @($Preference.AttackSurfaceReductionOnlyExclusions)
    }
    CFA = [pscustomobject]@{
      AllowedApplications = @($Preference.ControlledFolderAccessAllowedApplications)
      ProtectedFolders    = @($Preference.ControlledFolderAccessProtectedFolders)
    }
  }
}

function New-MinimumBaselineDesiredConfig {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$Preference
  )

  # Minimal baseline philosophy (safe by default):
  # - Do not add broad AV exclusions (Microsoft generally recommends avoiding unnecessary exclusions).
  # - Keep ASR-only exclusions empty (avoid weakening ASR without evidence).
  # - Keep CFA allow-app list empty (avoid allowing extra apps by default).
  # - Do not force protected folders here: Windows system folders are protected by default; forcing additional folders
  #   without context can cause app compatibility issues.
  #
  # Implementation:
  # - Desired = current lists (no removals), plus a minimal/empty baseline for the categories above.
  #   This prevents unintended removals, while ensuring a defined schema.
  $cur = New-NullSafeDesiredFromCurrent -Preference $Preference

  [pscustomobject]@{
    Defender = [pscustomobject]@{
      ExclusionPaths      = @($cur.Defender.ExclusionPaths)
      ExclusionProcesses  = @($cur.Defender.ExclusionProcesses)
      ExclusionExtensions = @($cur.Defender.ExclusionExtensions)
    }
    ASR = [pscustomobject]@{
      OnlyExclusions = @()   # baseline: none
    }
    CFA = [pscustomobject]@{
      AllowedApplications = @()  # baseline: none
      ProtectedFolders    = @()  # baseline: none (system defaults already exist) 
    }
  }
}

function Get-Config {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$Path)

  try {
    if (Test-Path -LiteralPath $Path) {
      return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    }

    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    $alt  = Join-Path (Split-Path -Parent $here) "config\CONFIG.json"
    if (Test-Path -LiteralPath $alt) {
      return Get-Content -Raw -LiteralPath $alt | ConvertFrom-Json
    }
  } catch {
    return $null
  }

  return $null
}

function Ensure-EventSource {
  [CmdletBinding()]
  param([string]$Source='Defender-Allowlist-Sync',[string]$Log='Application')

  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
      New-EventLog -LogName $Log -Source $Source | Out-Null
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
    [ValidateSet('Information','Warning','Error')][string]$Level='Information',
    [string]$Source='Defender-Allowlist-Sync',
    [bool]$EventLogReady = $false
  )

  try {
    if ($EventLogReady) {
      Write-EventLog -LogName Application -Source $Source -EntryType $Level -EventId $Id -Message $Msg
    } else {
      throw "EventLog source not available."
    }
  } catch {
    Write-Host "[$Level][$Id] $Msg"
  }
}

function Write-AuditJson {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][object]$Object
  )

  try {
    if ([string]::IsNullOrWhiteSpace($Path)) { return }

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
      New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    ($Object | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $Path -Encoding UTF8
  } catch {
  }
}

function To-NormList {
  [CmdletBinding()]
  param(
    [object]$Input,
    [ValidateSet('path','process','ext','generic','cfaapp')][string]$Kind='generic'
  )

  if (-not $Input) { return @() }

  $arr = New-Object System.Collections.Generic.List[string]
  foreach ($v in @($Input)) {
    if ($null -eq $v) { continue }
    $s = ([string]$v).Trim()
    if ([string]::IsNullOrWhiteSpace($s)) { continue }

    switch ($Kind) {
      'path' {
        $t = $s.TrimEnd('\')
        if ($t.Length -eq 2 -and $t -match '^[a-zA-Z]:$') { $t = $t + '\' }
        $arr.Add($t.ToLowerInvariant())
      }
      'process' { $arr.Add($s.ToLowerInvariant()) }
      'ext' {
        $t = $s.ToLowerInvariant()
        if ($t -notmatch '^\.' ) { $t = '.' + $t }
        $arr.Add($t)
      }
      'cfaapp' {
        $arr.Add($s.ToLowerInvariant())
      }
      default { $arr.Add($s) }
    }
  }

  return $arr | Where-Object { $_.Length -gt 0 } | Sort-Object -Unique
}

function Is-RiskyEntry {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$Item,
    [ValidateSet('path','process','ext','generic','cfaapp')][string]$Kind='generic'
  )

  $s = $Item.Trim().ToLowerInvariant()

  if ($s -match '[\*\?]') { return $true }
  if ($s -like '\\*') { return $true }
  if ($s -like '\\?\*') { return $true }
  if ($s -like '\device\*') { return $true }

  if ($Kind -in @('path','cfaapp')) {
    if ($s -match '^[a-z]:\\$') { return $true }
    if ($s -match '^[a-z]:\\\*$') { return $true }

    if ($s -eq 'c:\windows' -or $s -like 'c:\windows\*') { return $true }
    if ($s -eq 'c:\program files' -or $s -like 'c:\program files\*') { return $true }
    if ($s -eq 'c:\program files (x86)' -or $s -like 'c:\program files (x86)\*') { return $true }

    if ($s -like 'c:\users\*') { return $true }
  }

  if ($Kind -eq 'ext') {
    if ($s -in '.exe','.dll','.sys') { return $true }
  }

  return $false
}

function Diff-Lists {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][ValidateSet('path','process','ext','generic','cfaapp')][string]$Kind,
    [string[]]$Current,
    [object]$Desired
  )

  $cur    = To-NormList -Input $Current -Kind $Kind
  $desRaw = To-NormList -Input $Desired -Kind $Kind

  $bad = @($desRaw | Where-Object { Is-RiskyEntry -Item $_ -Kind $Kind })
  $des = @($desRaw | Where-Object { $bad -notcontains $_ })

  $toAdd    = @($des | Where-Object { $cur -notcontains $_ })
  $toRemove = @($cur | Where-Object { $des -notcontains $_ })

  [pscustomobject]@{
    Name     = $Name
    Kind     = $Kind
    Current  = $cur
    Desired  = $des
    ToAdd    = $toAdd
    ToRemove = $toRemove
    Rejected = $bad
  }
}

function Apply-Diff {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][pscustomobject]$Diff,
    [switch]$Remediate
  )

  $name   = [string]$Diff.Name
  $errors = New-Object System.Collections.Generic.List[string]

  if ($Remediate) {
    try {
      if ($Diff.ToAdd.Count -gt 0) {
        switch ($name) {
          'ExclusionPath'        { Add-MpPreference -ExclusionPath $Diff.ToAdd }
          'ExclusionProcess'     { Add-MpPreference -ExclusionProcess $Diff.ToAdd }
          'ExclusionExtension'   { Add-MpPreference -ExclusionExtension $Diff.ToAdd }
          'AttackSurfaceReductionOnlyExclusions' { Add-MpPreference -AttackSurfaceReductionOnlyExclusions $Diff.ToAdd }
          'ControlledFolderAccessAllowedApplications' { Add-MpPreference -ControlledFolderAccessAllowedApplications $Diff.ToAdd }
          'ControlledFolderAccessProtectedFolders'   { Add-MpPreference -ControlledFolderAccessProtectedFolders $Diff.ToAdd }
          default { }
        }
      }
    } catch {
      $errors.Add("Add failed for ${name}: $($_.Exception.Message)")
    }

    try {
      if ($Diff.ToRemove.Count -gt 0) {
        switch ($name) {
          'ExclusionPath'        { Remove-MpPreference -ExclusionPath $Diff.ToRemove }
          'ExclusionProcess'     { Remove-MpPreference -ExclusionProcess $Diff.ToRemove }
          'ExclusionExtension'   { Remove-MpPreference -ExclusionExtension $Diff.ToRemove }
          'AttackSurfaceReductionOnlyExclusions' { Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $Diff.ToRemove }
          'ControlledFolderAccessAllowedApplications' { Remove-MpPreference -ControlledFolderAccessAllowedApplications $Diff.ToRemove }
          'ControlledFolderAccessProtectedFolders'   { Remove-MpPreference -ControlledFolderAccessProtectedFolders $Diff.ToRemove }
          default { }
        }
      }
    } catch {
      $errors.Add("Remove failed for ${name}: $($_.Exception.Message)")
    }
  }

  [pscustomobject]@{
    Name     = $name
    Added    = @($Diff.ToAdd)
    Removed  = @($Diff.ToRemove)
    Rejected = @($Diff.Rejected)
    Errors   = @($errors)
  }
}

function Write-ConsoleSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][pscustomobject]$Result
  )

  function Write-Kv {
    param(
      [string]$Key,
      [string]$Value,
      [ConsoleColor]$KeyColor = [ConsoleColor]::DarkGray,
      [ConsoleColor]$ValueColor = [ConsoleColor]::Gray
    )
    Write-Host ("{0,-12}: " -f $Key) -ForegroundColor $KeyColor -NoNewline
    Write-Host $Value -ForegroundColor $ValueColor
  }

  $modeColor = if ($Result.Remediate) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Cyan }
  $resColor = switch ($Result.Result) {
    'OK_NO_DRIFT'          { [ConsoleColor]::Green; break }
    'REMEDIATION_OK'       { [ConsoleColor]::Green; break }
    'DRIFT_NO_REMEDIATION' { [ConsoleColor]::Yellow; break }
    'REMEDIATION_ERRORS'   { [ConsoleColor]::Red; break }
    'FAILED'               { [ConsoleColor]::Red; break }
    default                { [ConsoleColor]::Gray }
  }

  Write-Host ""
  Write-Host "============================================================" -ForegroundColor DarkGray
  Write-Host "Defender / ASR / CFA Allowlist Sync" -ForegroundColor White
  Write-Host "============================================================" -ForegroundColor DarkGray

  Write-Kv "Mode"       ($(if ($Result.Remediate) { "Remediate" } else { "AuditOnly" })) DarkGray $modeColor
  Write-Kv "Baseline"   $Result.BaselineUsed DarkGray ($(if ($Result.BaselineUsed -eq 'None') { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow }))
  Write-Kv "Computer"   $Result.ComputerName
  Write-Kv "Timestamp"  $Result.Timestamp
  Write-Kv "JSON"       $Result.SourceJson
  Write-Kv "Audit"      $Result.AuditPath

  Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
  Write-Kv "JsonLoaded" ([string]$Result.JsonLoaded) DarkGray ($(if ($Result.JsonLoaded) { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow }))
  if ($Result.JsonError) { Write-Kv "JsonError" $Result.JsonError DarkGray Yellow }

  Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
  Write-Kv "Add"        ([string]$Result.TotalAdd)      DarkGray ($(if ($Result.TotalAdd -gt 0) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green }))
  Write-Kv "Remove"     ([string]$Result.TotalRemove)   DarkGray ($(if ($Result.TotalRemove -gt 0) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green }))
  Write-Kv "Rejected"   ([string]$Result.TotalRejected) DarkGray ($(if ($Result.TotalRejected -gt 0) { [ConsoleColor]::Yellow } else { [ConsoleColor]::DarkGray }))
  Write-Kv "Errors"     ([string]$Result.TotalErrors)   DarkGray ($(if ($Result.TotalErrors -gt 0) { [ConsoleColor]::Red } else { [ConsoleColor]::DarkGray }))
  Write-Kv "Result"     $Result.Result                 DarkGray $resColor

  if ($Result.Notes -and $Result.Notes.Count -gt 0) {
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "Notes:" -ForegroundColor DarkGray
    foreach ($n in $Result.Notes) { Write-Host ("- " + $n) -ForegroundColor DarkGray }
  }

  if ($Result.PerCategory -and $Result.PerCategory.Count -gt 0) {
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "Per-category diff:" -ForegroundColor DarkGray
    foreach ($row in ($Result.PerCategory | Sort-Object Name)) {
      $aColor = if ($row.Add -gt 0) { 'Yellow' } else { 'DarkGray' }
      $rColor = if ($row.Remove -gt 0) { 'Yellow' } else { 'DarkGray' }
      $xColor = if ($row.Rejected -gt 0) { 'Yellow' } else { 'DarkGray' }

      Write-Host ("{0,-45}  Add={1,3}  Rem={2,3}  Rej={3,3}" -f $row.Name,$row.Add,$row.Remove,$row.Rejected) -ForegroundColor Gray
      if ($row.Add -gt 0 -or $row.Remove -gt 0 -or $row.Rejected -gt 0) {
        # Optional: highlight lines with changes (second line in color to avoid pipeline)
        Write-Host ("{0,-45}  Add={1,3}  Rem={2,3}  Rej={3,3}" -f "",$row.Add,$row.Remove,$row.Rejected) -ForegroundColor DarkGray
        Write-Host ("{0,-45}  Add={1,3}  Rem={2,3}  Rej={3,3}" -f "",$row.Add,$row.Remove,$row.Rejected) -ForegroundColor DarkGray
      }

      # Keep it simple: single line; colors per field are not possible without multiple Write-Host calls.
      # We already color the totals and overall result.
    }
  }

  Write-Host "============================================================" -ForegroundColor DarkGray
  Write-Host ""
}

# ----------------------------- Main ------------------------------------------------

$eventLogReady = Ensure-EventSource

try {
  if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
    throw "Defender PowerShell module/cmdlets not available (Get-MpPreference missing)."
  }

  $pref = Get-MpPreference

  $cfg = Get-Config -Path $ConfigPath
  if (-not $ExceptionsPath) {
    if ($cfg -and $cfg.DefenderAllowlistPath) { $ExceptionsPath = [string]$cfg.DefenderAllowlistPath }
    elseif ($cfg -and $cfg.DefenderAllowListPath) { $ExceptionsPath = [string]$cfg.DefenderAllowListPath }
  }

  $sourceJson = $(if ($ExceptionsPath) { $ExceptionsPath } else { "PATH/TO/JSON (not provided)" })

  $jsonLoaded   = $false
  $jsonError    = $null
  $baselineUsed = 'None'
  $notes        = New-Object System.Collections.Generic.List[string]
  $desired      = $null

  if ($ExceptionsPath -and (Test-Path -LiteralPath $ExceptionsPath)) {
    try {
      $raw = Get-Content -Raw -LiteralPath $ExceptionsPath
      if ([string]::IsNullOrWhiteSpace($raw)) {
        $jsonError = "Allowlist JSON file is empty."
        if ($StrictJson) { throw $jsonError }
        $baselineUsed = $BaselineMode
      } else {
        $desired = $raw | ConvertFrom-Json
        $jsonLoaded = $true
      }
    } catch {
      $jsonError = $_.Exception.Message
      if ($StrictJson) { throw $jsonError }
      $baselineUsed = $BaselineMode
    }
  } else {
    $jsonError = "Allowlist JSON not found."
    if ($StrictJson) { throw $jsonError }
    $baselineUsed = $BaselineMode
  }

  if (-not $jsonLoaded) {
    switch ($BaselineMode) {
      'Current' {
        $notes.Add("No usable JSON; baseline applied: desired state equals current state (no changes).")
        $desired = New-NullSafeDesiredFromCurrent -Preference $pref
      }
      'Minimum' {
        $notes.Add("No usable JSON; baseline applied: minimum baseline (conservative, no broad default exclusions).")
        $desired = New-MinimumBaselineDesiredConfig -Preference $pref
      }
    }
  }

  if (-not $desired) {
    $baselineUsed = 'DefaultSchema'
    $notes.Add("Internal fallback used (empty schema).")
    $desired = New-DefaultDesiredConfig
  }

  $jDef = $desired.Defender
  $jAsr = $desired.ASR
  $jCfa = $desired.CFA

  $diffs = @()
  $diffs += Diff-Lists -Name 'ExclusionPath'        -Kind 'path'    -Current $pref.ExclusionPath      -Desired $jDef.ExclusionPaths
  $diffs += Diff-Lists -Name 'ExclusionProcess'     -Kind 'process' -Current $pref.ExclusionProcess   -Desired $jDef.ExclusionProcesses
  $diffs += Diff-Lists -Name 'ExclusionExtension'   -Kind 'ext'     -Current $pref.ExclusionExtension -Desired $jDef.ExclusionExtensions
  $diffs += Diff-Lists -Name 'AttackSurfaceReductionOnlyExclusions' -Kind 'path'   -Current $pref.AttackSurfaceReductionOnlyExclusions -Desired $jAsr.OnlyExclusions
  $diffs += Diff-Lists -Name 'ControlledFolderAccessAllowedApplications' -Kind 'cfaapp' -Current $pref.ControlledFolderAccessAllowedApplications -Desired $jCfa.AllowedApplications
  $diffs += Diff-Lists -Name 'ControlledFolderAccessProtectedFolders'   -Kind 'path'   -Current $pref.ControlledFolderAccessProtectedFolders   -Desired $jCfa.ProtectedFolders

  $totalAdd = [int](($diffs | ForEach-Object { $_.ToAdd.Count } | Measure-Object -Sum).Sum)
  $totalRem = [int](($diffs | ForEach-Object { $_.ToRemove.Count } | Measure-Object -Sum).Sum)
  $totalBad = [int](($diffs | ForEach-Object { $_.Rejected.Count } | Measure-Object -Sum).Sum)

  $resultCode = $null
  $results    = @()
  $errsFlat   = @()

  if (($totalAdd + $totalRem + $totalBad) -eq 0) {
    $resultCode = "OK_NO_DRIFT"
    Write-HealthEvent -Id 3200 -Msg "Defender/ASR allowlist OK: no drift. JSON=$sourceJson Audit=$AuditPath" -Level Information -EventLogReady:$eventLogReady
  }
  elseif (-not $Remediate) {
    $resultCode = "DRIFT_NO_REMEDIATION"
    Write-HealthEvent -Id 3210 -Msg "Defender/ASR allowlist drift: add=$totalAdd remove=$totalRem rejected=$totalBad (no remediation). JSON=$sourceJson Audit=$AuditPath" -Level Warning -EventLogReady:$eventLogReady
  }
  else {
    foreach ($d in $diffs) { $results += Apply-Diff -Diff $d -Remediate:$true }
    $errsFlat = @($results | ForEach-Object { $_.Errors } | Where-Object { $_ -and $_.Length -gt 0 })

    if ($errsFlat.Count -gt 0) {
      $resultCode = "REMEDIATION_ERRORS"
      Write-HealthEvent -Id 3210 -Msg ("Defender/ASR allowlist sync completed with errors. add=$totalAdd remove=$totalRem rejected=$totalBad JSON=$sourceJson Audit=$AuditPath`r`nErrors: " + ($errsFlat -join ' | ')) -Level Error -EventLogReady:$eventLogReady
    } else {
      $resultCode = "REMEDIATION_OK"
      Write-HealthEvent -Id 3200 -Msg "Defender/ASR allowlist sync OK. add=$totalAdd remove=$totalRem rejected=$totalBad JSON=$sourceJson Audit=$AuditPath" -Level Information -EventLogReady:$eventLogReady
    }
  }

  $perCategory = $diffs | ForEach-Object {
    [pscustomobject]@{
      Name     = $_.Name
      Add      = [int]$_.ToAdd.Count
      Remove   = [int]$_.ToRemove.Count
      Rejected = [int]$_.Rejected.Count
    }
  }

  $final = [pscustomobject]@{
    Timestamp     = (Get-Date).ToString("o")
    ComputerName  = $env:COMPUTERNAME
    Remediate     = [bool]$Remediate
    SourceJson    = $sourceJson
    AuditPath     = $AuditPath
    JsonLoaded    = [bool]$jsonLoaded
    JsonError     = $jsonError
    BaselineUsed  = $baselineUsed
    Notes         = @($notes)

    TotalAdd      = $totalAdd
    TotalRemove   = $totalRem
    TotalRejected = $totalBad
    TotalErrors   = [int]@($errsFlat).Count
    Result        = $resultCode

    Diffs         = $diffs
    Results       = $results
    ErrorsFlat    = $errsFlat
    PerCategory   = $perCategory
  }

  Write-AuditJson -Path $AuditPath -Object $final
  Write-ConsoleSummary -Result $final

  if ($Passthru) { $final }
}
catch {
  $msg = "Defender/ASR allowlist failed: $($_.Exception.Message)"
  Write-HealthEvent -Id 3210 -Msg $msg -Level Error -EventLogReady:$eventLogReady

  $final = [pscustomobject]@{
    Timestamp     = (Get-Date).ToString("o")
    ComputerName  = $env:COMPUTERNAME
    Remediate     = [bool]$Remediate
    SourceJson    = $(if ($ExceptionsPath) { $ExceptionsPath } else { "PATH/TO/JSON (unknown)" })
    AuditPath     = $AuditPath
    JsonLoaded    = $false
    JsonError     = $msg
    BaselineUsed  = 'None'
    Notes         = @()

    TotalAdd      = 0
    TotalRemove   = 0
    TotalRejected = 0
    TotalErrors   = 1
    Result        = "FAILED"

    Diffs         = @()
    Results       = @()
    ErrorsFlat    = @($msg)
    PerCategory   = @()
  }

  Write-AuditJson -Path $AuditPath -Object $final
  Write-ConsoleSummary -Result $final

  if ($Passthru) { $final }
}
