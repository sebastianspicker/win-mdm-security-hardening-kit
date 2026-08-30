#requires -version 5.1
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

.PARAMETER ConfigPath
  Path to an optional configuration JSON file that can contain the path to the allowlist JSON.
  This is a convenience input for centralized deployments.

.PARAMETER ExceptionsPath
  Path to the allowlist JSON file that defines the desired state.
  If provided, it takes precedence over any path discovered via -ConfigPath.

.PARAMETER AuditPath
  Path to a JSON file that will receive an audit record of the run.
  If the directory does not exist, it is created.

.PARAMETER PassThru
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


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER Strict
  Treat warnings as failures.

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
  None by default.

  When -PassThru is used:
  - A single PSCustomObject with properties such as:
    Timestamp, ComputerName, Remediate, SourceJson, AuditPath,
    JsonLoaded, JsonError, BaselineUsed, Notes,
    TotalAdd, TotalRemove, TotalRejected, TotalErrors, Result,
    Diffs, Results, ErrorsFlat, PerCategory

.INPUTS
  None. This script does not accept pipeline input.

.EXAMPLE
  # Audit-only: show drift (no changes applied)
  .\scripts\01-ASR-Defender-Allowlist.ps1 -ExceptionsPath .\examples\configs\asr-defender-allowlist.json

.EXAMPLE
  # Remediate: apply the diff to match the JSON allowlist
  .\scripts\01-ASR-Defender-Allowlist.ps1 -ExceptionsPath .\examples\configs\asr-defender-allowlist.json -Mode Remediate

.EXAMPLE
  # Audit with the minimum fallback and no external JSON
  .\scripts\01-ASR-Defender-Allowlist.ps1 -BaselineMode Minimum

.EXAMPLE
  # Enforce strict JSON loading (fail if JSON is missing/invalid)
  .\scripts\01-ASR-Defender-Allowlist.ps1 -ExceptionsPath .\examples\configs\asr-defender-allowlist.json -StrictJson

.EXAMPLE
  # Emit structured output for reporting
  .\scripts\01-ASR-Defender-Allowlist.ps1 -ExceptionsPath .\examples\configs\asr-defender-allowlist.json -PassThru | ConvertTo-Json -Depth 6

.EXAMPLE
  # Emit structured output and export a compact report
  .\scripts\01-ASR-Defender-Allowlist.ps1 -ExceptionsPath .\examples\configs\asr-defender-allowlist.json -PassThru |
    Select-Object Timestamp,ComputerName,Result,TotalAdd,TotalRemove,TotalRejected,TotalErrors,SourceJson |
    Export-Csv -NoTypeInformation -Path .\asr-defender-allowlist.csv

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


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(

  # Optional config paths - use $null to skip, or provide actual paths
  [string]$ConfigPath,
  [string]$ExceptionsPath,
  [string]$AuditPath,

  [switch]$PassThru,
  [switch]$StrictJson,

  [ValidateSet('Current','Minimum')]
  [string]$BaselineMode = 'Minimum'

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '01-ASR-Defender-Allowlist.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor -DeriveRemediate
$Remediate = [bool]$script:__V2Context.Remediate
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
  $result = Get-V2ResultObject -ScriptName '01-ASR-Defender-Allowlist.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# ----------------------------- Helpers --------------------------------------------

function Get-DefaultDesiredConfig {
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

function Get-NullSafeDesiredFromCurrent {
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

function Get-MinimumBaselineDesiredConfig {
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
  # Preserve current lists so the default does not remove operator-managed state.
  $cur = Get-NullSafeDesiredFromCurrent -Preference $Preference

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
  param([AllowEmptyString()][string]$Path)

  try {
    $sanitized = if ([string]::IsNullOrWhiteSpace($Path)) { $null } else { Sanitize-Path -Path $Path -MustExist }
    if ($sanitized) {
      return Get-BoundedUtf8FileContent -Path $sanitized -MaximumBytes 1048576 | ConvertFrom-Json
    }
  } catch {
    return $null
  }

  return $null
}


function Write-AuditJson {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Path,
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
    Write-Verbose ("ASR JSON save failed for '{0}': {1}" -f $Path,$_.Exception.Message)
  }
}

function To-NormList {
  [CmdletBinding()]
  param(
    [Alias('Input')]
    [object]$InputValue,
    [ValidateSet('path','process','ext','generic','cfaapp')][string]$Kind='generic'
  )

  if (-not $InputValue) { return @() }

  $arr = New-Object System.Collections.Generic.List[string]
  foreach ($v in @($InputValue)) {
    if ($null -eq $v) { continue }
    $s = ([string]$v).Trim()
    if ([string]::IsNullOrWhiteSpace($s)) { continue }

    switch ($Kind) {
      'path' {
        $t = $s.TrimEnd('\','/')
        if ($t.Length -eq 2 -and $t -match '^[a-zA-Z]:$') { $t = $t + '\' }
        # For UNC paths, ensure we don't accidentally trim the root if it was just \\server\share\
        if ($s -like '\\*\*' -and $t -notlike '\\*\*') { $t = $s } 
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
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory=$true)][pscustomobject]$Diff,
    [switch]$Remediate
  )

  $name   = [string]$Diff.Name
  $errors = New-Object System.Collections.Generic.List[string]

  if ($Remediate) {
    try {
      if ($Diff.ToAdd.Count -gt 0) {
        if ($PSCmdlet.ShouldProcess($name, "Add Defender allowlist entries")) {
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
      }
    } catch {
      $errors.Add("Add failed for ${name}: $($_.Exception.Message)")
    }

    try {
      if ($Diff.ToRemove.Count -gt 0) {
        if ($PSCmdlet.ShouldProcess($name, "Remove Defender allowlist entries")) {
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

# ----------------------------- Main ------------------------------------------------
$script:Findings = Get-FindingsList
if (-not (Ensure-EventSource)) {
  Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
}

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $final = [pscustomobject]@{
    Timestamp     = (Get-Date).ToString("o")
    ComputerName  = $env:COMPUTERNAME
    Remediate     = [bool]$Remediate
    SourceJson    = $(if ($ExceptionsPath) { $ExceptionsPath } else { "(not provided)" })
    AuditPath     = $AuditPath
    JsonLoaded    = $false
    JsonError     = $null
    BaselineUsed  = 'UnsupportedHost'
    Notes         = @('Skipped: Microsoft Defender allowlist auditing is only supported on Windows hosts.')
    TotalAdd      = 0
    TotalRemove   = 0
    TotalRejected = 0
    TotalErrors   = 0
    Result        = 'OK_NO_DRIFT'
    Diffs         = @()
    Results       = @()
    ErrorsFlat    = @()
    PerCategory   = @()
  }

  Write-AuditJson -Path $AuditPath -Object $final
  $summaryObj = [pscustomobject]@{ ComputerName = $final.ComputerName; Timestamp = $final.Timestamp }
  $findingsAL = ConvertTo-ArrayList -InputObject $script:Findings
  Write-ConsoleSummary -Summary $summaryObj -Findings $findingsAL `
    -CustomFields ([ordered]@{
      Mode       = $(if ($final.Remediate) { 'Remediate' } else { 'Audit' })
      Baseline   = $final.BaselineUsed
      JSON       = $final.SourceJson
      Audit      = $final.AuditPath
      JsonLoaded = [string]$final.JsonLoaded
      Add        = [string]$final.TotalAdd
      Remove     = [string]$final.TotalRemove
      Rejected   = [string]$final.TotalRejected
      Errors     = [string]$final.TotalErrors
      Result     = $final.Result
    })
  if ($final.Notes -and $final.Notes.Count -gt 0) {
    Write-UiLine "Notes:" -ForegroundColor DarkGray
    foreach ($n in $final.Notes) { Write-UiLine ("- " + $n) -ForegroundColor DarkGray }
  }
  if ($final.PerCategory -and $final.PerCategory.Count -gt 0) {
    Write-UiLine "Per-category diff:" -ForegroundColor DarkGray
    foreach ($row in ($final.PerCategory | Sort-Object Name)) {
      Write-UiLine ("{0,-45}  Add={1,3}  Rem={2,3}  Rej={3,3}" -f $row.Name,$row.Add,$row.Remove,$row.Rejected) -ForegroundColor Gray
    }
  }
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $v2Result = Get-V2ResultObject -ScriptName '01-ASR-Defender-Allowlist.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $final -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

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

  $sourceJson = $(if ($ExceptionsPath) { $ExceptionsPath } else { "(not provided)" })

  $jsonLoaded   = $false
  $jsonError    = $null
  $baselineUsed = 'None'
  $notes        = New-Object System.Collections.Generic.List[string]
  $desired      = $null

  if ($ExceptionsPath -and (Test-Path -LiteralPath $ExceptionsPath)) {
    try {
      $raw = Get-BoundedUtf8FileContent -Path $ExceptionsPath -MaximumBytes 1048576
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
        $desired = Get-NullSafeDesiredFromCurrent -Preference $pref
      }
      'Minimum' {
        $notes.Add("No usable JSON; baseline applied: minimum baseline (conservative, no broad default exclusions).")
        $desired = Get-MinimumBaselineDesiredConfig -Preference $pref
      }
    }
  }

  if (-not $desired) {
    $baselineUsed = 'DefaultSchema'
    $notes.Add("Internal fallback used (empty schema).")
    $desired = Get-DefaultDesiredConfig
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
    $null = Write-HealthEvent -Id 3200 -Msg "Defender/ASR allowlist OK: no drift. JSON=$sourceJson Audit=$AuditPath" -Level Information
  }
  elseif (-not $Remediate) {
    $resultCode = "DRIFT_NO_REMEDIATION"
    $null = Write-HealthEvent -Id 3210 -Msg "Defender/ASR allowlist drift: add=$totalAdd remove=$totalRem rejected=$totalBad (no remediation). JSON=$sourceJson Audit=$AuditPath" -Level Warning
    foreach ($d in $diffs) {
        if ($d.ToAdd.Count -gt 0) { Add-Finding -FindingList $script:Findings -Code 'ASR-Drift-Add' -Severity 'Low' -Message "ASR drift (missing): $($d.Name)" -Extra @{ Missing = $d.ToAdd } }
        if ($d.ToRemove.Count -gt 0) { Add-Finding -FindingList $script:Findings -Code 'ASR-Drift-Remove' -Severity 'Low' -Message "ASR drift (extra): $($d.Name)" -Extra @{ Extra = $d.ToRemove } }
        if ($d.Rejected.Count -gt 0) { Add-Finding -FindingList $script:Findings -Code 'ASR-Rejected' -Severity 'Medium' -Message "ASR risky entry rejected: $($d.Name)" -Extra @{ Rejected = $d.Rejected } }
    }
  }
  else {
    foreach ($d in $diffs) { $results += Apply-Diff -Diff $d -Remediate:$true }
    $errsFlat = @($results | ForEach-Object { $_.Errors } | Where-Object { $_ -and $_.Length -gt 0 })

    if ($errsFlat.Count -gt 0) {
      $resultCode = "REMEDIATION_ERRORS"
      $null = Write-HealthEvent -Id 3210 -Msg ("Defender/ASR allowlist sync completed with errors. add=$totalAdd remove=$totalRem rejected=$totalBad JSON=$sourceJson Audit=$AuditPath`r`nErrors: " + ($errsFlat -join ' | ')) -Level Error
    } else {
      $resultCode = "REMEDIATION_OK"
      $null = Write-HealthEvent -Id 3200 -Msg "Defender/ASR allowlist sync OK. add=$totalAdd remove=$totalRem rejected=$totalBad JSON=$sourceJson Audit=$AuditPath" -Level Information
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
  $summaryObj = [pscustomobject]@{ ComputerName = $final.ComputerName; Timestamp = $final.Timestamp }
  $findingsAL = ConvertTo-ArrayList -InputObject $script:Findings
  Write-ConsoleSummary -Summary $summaryObj -Findings $findingsAL `
    -CustomFields ([ordered]@{
      Mode       = $(if ($final.Remediate) { 'Remediate' } else { 'Audit' })
      Baseline   = $final.BaselineUsed
      JSON       = $final.SourceJson
      Audit      = $final.AuditPath
      JsonLoaded = [string]$final.JsonLoaded
      Add        = [string]$final.TotalAdd
      Remove     = [string]$final.TotalRemove
      Rejected   = [string]$final.TotalRejected
      Errors     = [string]$final.TotalErrors
      Result     = $final.Result
    })
  if ($final.Notes -and $final.Notes.Count -gt 0) {
    Write-UiLine "Notes:" -ForegroundColor DarkGray
    foreach ($n in $final.Notes) { Write-UiLine ("- " + $n) -ForegroundColor DarkGray }
  }
  if ($final.PerCategory -and $final.PerCategory.Count -gt 0) {
    Write-UiLine "Per-category diff:" -ForegroundColor DarkGray
    foreach ($row in ($final.PerCategory | Sort-Object Name)) {
      Write-UiLine ("{0,-45}  Add={1,3}  Rem={2,3}  Rej={3,3}" -f $row.Name,$row.Add,$row.Remove,$row.Rejected) -ForegroundColor Gray
    }
  }

}
catch {
  $msg = "Defender/ASR allowlist failed: $($_.Exception.Message)"
  $null = Write-HealthEvent -Id 3210 -Msg $msg -Level Error

  $final = [pscustomobject]@{
    Timestamp     = (Get-Date).ToString("o")
    ComputerName  = $env:COMPUTERNAME
    Remediate     = [bool]$Remediate
    SourceJson    = $(if ($ExceptionsPath) { $ExceptionsPath } else { "(not provided)" })
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
  $summaryObj = [pscustomobject]@{ ComputerName = $final.ComputerName; Timestamp = $final.Timestamp }
  $findingsAL = ConvertTo-ArrayList -InputObject $script:Findings
  Write-ConsoleSummary -Summary $summaryObj -Findings $findingsAL `
    -CustomFields ([ordered]@{
      Mode       = $(if ($final.Remediate) { 'Remediate' } else { 'Audit' })
      Baseline   = $final.BaselineUsed
      JSON       = $final.SourceJson
      Audit      = $final.AuditPath
      JsonLoaded = [string]$final.JsonLoaded
      Add        = [string]$final.TotalAdd
      Remove     = [string]$final.TotalRemove
      Rejected   = [string]$final.TotalRejected
      Errors     = [string]$final.TotalErrors
      Result     = $final.Result
    })
  if ($final.Notes -and $final.Notes.Count -gt 0) {
    Write-UiLine "Notes:" -ForegroundColor DarkGray
    foreach ($n in $final.Notes) { Write-UiLine ("- " + $n) -ForegroundColor DarkGray }
  }
  if ($final.PerCategory -and $final.PerCategory.Count -gt 0) {
    Write-UiLine "Per-category diff:" -ForegroundColor DarkGray
    foreach ($row in ($final.PerCategory | Sort-Object Name)) {
      Write-UiLine ("{0,-45}  Add={1,3}  Rem={2,3}  Rej={3,3}" -f $row.Name,$row.Add,$row.Remove,$row.Rejected) -ForegroundColor Gray
    }
  }
}

# V2 output contract
$resultToken = if ($final.Result -eq 'FAILED') { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
$v2Result = Get-V2ResultObject -ScriptName '01-ASR-Defender-Allowlist.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $final -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
