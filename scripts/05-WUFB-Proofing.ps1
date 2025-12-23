<#
.SYNOPSIS
  Audits and optionally remediates Windows Update policy registry settings to enforce a desired update source
  (Windows Update for Business or WSUS) and related policy intent, then writes a proof JSON and prints a
  human-readable summary.

.DESCRIPTION
  This script reads a "catalog" JSON (baseline/desired state) and compares it with the current Windows Update
  policy registry configuration under HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate (and subkeys).

  It can run in two modes:
  - Audit mode (default): Detects drift only and produces a DRIFT result when differences are found.
  - Remediation mode (-Remediate): Applies idempotent registry changes to match the catalog and reports changes.

  The script always:
  - Collects evidence (selected registry values and basic OS information).
  - Writes a proof JSON file (path configurable in the catalog; safe defaults are used if missing/invalid).
  - Prints a colored console summary (intended for humans).

  Pipeline behavior:
  - By default, the script writes no objects to the pipeline (console output only).
  - With -PassThru, the script emits exactly one structured object suitable for Export-Csv/ConvertTo-Json/etc.

  Catalog loading behavior:
  - If -CatalogPath is provided, that file is used as the catalog.
  - Otherwise, -ConfigPath may be used to point to a configuration JSON that references a catalog path.
  - If no valid JSON can be loaded, built-in defaults are used so the script remains functional.

.PARAMETER CatalogPath
  Path to a baseline catalog JSON file describing the desired Windows Update policy intent.
  If the file doesn't exist or cannot be parsed, the script falls back to built-in defaults.

.PARAMETER ConfigPath
  Path to a configuration JSON file.
  The config may reference a catalog file path (for example: config.WUfB.CatalogPath).
  If the config doesn't exist or cannot be parsed, the script falls back to built-in defaults unless -CatalogPath
  was provided.

.PARAMETER Remediate
  Enables remediation mode.
  When set, the script applies registry changes to match the desired state from the catalog.
  Without this switch, the script runs in audit-only mode and never modifies policy values.

.PARAMETER Strict
  Changes result handling when drift is detected.
  - Without -Strict: drift is reported as DRIFT (useful for audit reporting without failing a pipeline).
  - With -Strict: drift is treated as WARNING and the script exits with a non-zero status code to signal attention.

.PARAMETER PassThru
  Emits one structured result object to the pipeline at the end of the run.
  The object includes the overall result, counts, proof path, evidence snapshot, the loaded catalog, and lists of
  drift/changes/notes.

.OUTPUTS
  By default, this script outputs nothing to the pipeline (console output only).

  With -PassThru, this script outputs a single PSCustomObject with (at minimum) the following properties:
  - Time, Hostname
  - Result, Elevated, Remediate, Strict
  - HasDrift, DriftCount, ChangesCount, NotesCount
  - ProofPath, EventLog
  - Drift (string[]), Changes (string[]), Notes (string[])
  - Evidence (hashtable/object), Catalog (object), Operations (object[])

.EXAMPLE
  # Audit only using built-in defaults (no JSON required)
  .\05-WUFB-Proofing.ps1

.EXAMPLE
  # Audit using an explicit catalog JSON
  .\05-WUFB-Proofing.ps1 -CatalogPath "PATH/TO/CATALOG.json"

.EXAMPLE
  # Audit using a config JSON that references a catalog path
  .\05-WUFB-Proofing.ps1 -ConfigPath "PATH/TO/CONFIG.json"

.EXAMPLE
  # Remediate and show structured output for further processing
  .\05-WUFB-Proofing.ps1 -CatalogPath "PATH/TO/CATALOG.json" -Remediate -PassThru

.EXAMPLE
  # Integrate in reporting pipelines (one object only)
  .\05-WUFB-Proofing.ps1 -PassThru | ConvertTo-Json -Depth 6

.EXAMPLE
  # Export a single-run result to CSV (flattening may be required for nested properties)
  .\05-WUFB-Proofing.ps1 -PassThru | Select-Object Time,Hostname,Result,HasDrift,DriftCount,ChangesCount,ProofPath | Export-Csv -NoTypeInformation -Path "PATH/TO/report.csv"

.NOTES
  Requires local administrator privileges only for operations that write to HKLM policy registry keys and for
  registering/writing to a Windows Event Log source (if enabled by the script).
  If not elevated, the script can still audit but remediation may fail and is reported accordingly.

  Exit codes:
  - 0: Completed successfully (OK or DRIFT in non-strict mode).
  - 1: Error (a failure occurred during processing or remediation).
  - 2: Warning (drift detected in strict mode).

  Proof output:
  - A proof JSON is written even in error cases (best effort), using a safe fallback path when necessary.
#>


[CmdletBinding()]
param(
  [string]$CatalogPath,
  [string]$ConfigPath = "PATH/TO/CONFIG.json",
  [switch]$Remediate,
  [switch]$Strict,
  [switch]$PassThru
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# -----------------------------
# Console helpers (no pipeline)
# -----------------------------

function Write-Console {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Message,

    [ConsoleColor]$ForegroundColor = [ConsoleColor]::Gray,

    [switch]$NoNewline
  )
  if ($NoNewline) {
    Write-Host $Message -ForegroundColor $ForegroundColor -NoNewline
  } else {
    Write-Host $Message -ForegroundColor $ForegroundColor
  }
}

function Write-ConsoleInfo {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Message
  )
  Write-Information $Message -InformationAction Continue
}

function Write-Rule {
  [CmdletBinding()]
  param(
    [string]$Title,
    [ConsoleColor]$Color = [ConsoleColor]::DarkCyan
  )
  $line = ('=' * 78)
  Write-Console $line -ForegroundColor $Color
  if ($Title) { Write-Console $Title -ForegroundColor $Color }
  Write-Console $line -ForegroundColor $Color
}

function Write-KV {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Key,
    [AllowEmptyString()][string]$Value,
    [ConsoleColor]$KeyColor = [ConsoleColor]::DarkGray,
    [ConsoleColor]$ValueColor = [ConsoleColor]::Gray
  )
  Write-Console ("{0,-12}: " -f $Key) -ForegroundColor $KeyColor -NoNewline
  Write-Console ("{0}" -f $Value) -ForegroundColor $ValueColor
}

function Write-ConsoleSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Summary,
    [AllowEmptyCollection()][string[]]$Changes,
    [AllowEmptyCollection()][string[]]$Drift,
    [AllowEmptyCollection()][string[]]$Notes
  )

  $result = [string]$Summary.Result
  $resColor = [ConsoleColor]::Gray
  if ($result -eq 'OK') { $resColor = [ConsoleColor]::Green }
  elseif ($result -eq 'DRIFT') { $resColor = [ConsoleColor]::Yellow }
  elseif ($result -eq 'WARNING') { $resColor = [ConsoleColor]::Yellow }
  elseif ($result -eq 'ERROR') { $resColor = [ConsoleColor]::Red }

  Write-Console ""
  Write-Rule -Title "WUfB Proofing Summary" -Color ([ConsoleColor]::DarkCyan)

  Write-KV -Key 'Result'    -Value $Summary.Result -ValueColor $resColor
  Write-KV -Key 'Elevated'  -Value $Summary.Elevated
  Write-KV -Key 'Remediate' -Value $Summary.Remediate
  Write-KV -Key 'Strict'    -Value $Summary.Strict
  Write-KV -Key 'Changes'   -Value $Summary.ChangesCount
  Write-KV -Key 'Drift'     -Value $Summary.DriftCount
  Write-KV -Key 'Notes'     -Value $Summary.NotesCount
  Write-KV -Key 'EventLog'  -Value $Summary.EventLogStatus
  Write-KV -Key 'Proof JSON'-Value $Summary.ProofPath

  if ($Changes -and $Changes.Count -gt 0) {
    Write-Console ""
    Write-Console "Changes:" -ForegroundColor ([ConsoleColor]::Green)
    foreach ($c in $Changes) { Write-Console ("- {0}" -f $c) -ForegroundColor ([ConsoleColor]::Gray) }
  }

  if ($Drift -and $Drift.Count -gt 0) {
    Write-Console ""
    Write-Console "Drift:" -ForegroundColor ([ConsoleColor]::Yellow)
    foreach ($d in $Drift) { Write-Console ("- {0}" -f $d) -ForegroundColor ([ConsoleColor]::Gray) }
  }

  if ($Notes -and $Notes.Count -gt 0) {
    Write-Console ""
    Write-Console "Notes:" -ForegroundColor ([ConsoleColor]::Cyan)
    foreach ($n in $Notes) { Write-Console ("- {0}" -f $n) -ForegroundColor ([ConsoleColor]::Gray) }
  }

  Write-Console ""
}

# -----------------------------
# Event log (best-effort)
# -----------------------------

function Ensure-EventSource {
  [CmdletBinding()]
  param(
    [string]$Source = 'WUfB-Proofing',
    [string]$Log    = 'Application'
  )
  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
      New-EventLog -LogName $Log -Source $Source -ErrorAction Stop | Out-Null
    }
    return $true
  } catch {
    return $false
  }
}

function Write-HealthEvent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][int]$Id,
    [Parameter(Mandatory)][string]$Msg,
    [ValidateSet('Information','Warning','Error')][string]$Level = 'Information',
    [string]$Source = 'WUfB-Proofing'
  )
  try {
    Write-EventLog -LogName Application -Source $Source -EntryType $Level -EventId $Id -Message $Msg
    return $true
  } catch {
    return $false
  }
}

# -----------------------------
# Security / registry / file helpers
# -----------------------------

function Is-Admin {
  [CmdletBinding()]
  param()
  try {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Ensure-Dir {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Ensure-Key {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -Path $Path -Force | Out-Null
  }
}

function Get-REG {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name
  )
  try { (Get-ItemProperty -Path $Path -ErrorAction Stop).$Name } catch { $null }
}

function Set-REGDWORD {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][int]$Value,
    [switch]$Remediate
  )

  Ensure-Key -Path $Path
  $cur = Get-REG -Path $Path -Name $Name

  if ($cur -eq $Value) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$false; Message=$null; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='None' }
  }

  if (-not $Remediate) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="$Path\$Name drift ($cur != $Value)"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Detect' }
  }

  try {
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
    return [pscustomobject]@{ Ok=$true; Changed=$true; Drift=$false; Message="Set $Path\$Name=$Value"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='SetDword' }
  } catch {
    return [pscustomobject]@{ Ok=$false; Changed=$false; Drift=$false; Message="Set $Path\$Name failed: $($_.Exception.Message)"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Error' }
  }
}

function Set-REGSZ {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Value,
    [switch]$Remediate
  )

  Ensure-Key -Path $Path
  $cur = Get-REG -Path $Path -Name $Name

  if ($cur -eq $Value) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$false; Message=$null; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='None' }
  }

  if (-not $Remediate) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="$Path\$Name drift ($cur != '$Value')"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Detect' }
  }

  try {
    New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force | Out-Null
    return [pscustomobject]@{ Ok=$true; Changed=$true; Drift=$false; Message="Set $Path\$Name='$Value'"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='SetString' }
  } catch {
    return [pscustomobject]@{ Ok=$false; Changed=$false; Drift=$false; Message="Set $Path\$Name failed: $($_.Exception.Message)"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Error' }
  }
}

function Remove-REGValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [switch]$Remediate
  )

  Ensure-Key -Path $Path
  $cur = Get-REG -Path $Path -Name $Name

  if ($null -eq $cur) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$false; Message=$null; Path=$Path; Name=$Name; Current=$cur; Desired=$null; Action='None' }
  }

  if (-not $Remediate) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="$Path\$Name should be absent, but is present ($cur)"; Path=$Path; Name=$Name; Current=$cur; Desired=$null; Action='Detect' }
  }

  try {
    Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
    return [pscustomobject]@{ Ok=$true; Changed=$true; Drift=$false; Message="Removed $Path\$Name"; Path=$Path; Name=$Name; Current=$cur; Desired=$null; Action='RemoveValue' }
  } catch {
    return [pscustomobject]@{ Ok=$false; Changed=$false; Drift=$false; Message="Remove $Path\$Name failed: $($_.Exception.Message)"; Path=$Path; Name=$Name; Current=$cur; Desired=$null; Action='Error' }
  }
}

function Save-JsonNoBom {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$Obj,
    [Parameter(Mandatory)][string]$Path
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { throw "Proof path is empty." }

  $fullPath = $Path
  try { $fullPath = [System.IO.Path]::GetFullPath($Path) } catch {}

  $parent = Split-Path -Parent $fullPath
  if ([string]::IsNullOrWhiteSpace($parent)) { throw "Invalid proof path (no parent folder): $fullPath" }

  Ensure-Dir -Path $parent

  $json = $Obj | ConvertTo-Json -Depth 12
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($fullPath, $json, $utf8NoBom)

  return $fullPath
}

function Add-Result {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][pscustomobject]$Result,
    [Parameter(Mandatory)][AllowEmptyCollection()]$Changes,
    [Parameter(Mandatory)][AllowEmptyCollection()]$Drifts,
    [Parameter(Mandatory)][ref]$Ok,
    [Parameter(Mandatory)][AllowEmptyCollection()]$Ops
  )

  $Ops.Add($Result) | Out-Null

  if ($Result.Message) {
    if ($Result.Changed) { $Changes.Add($Result.Message) | Out-Null }
    if ($Result.Drift)   { $Drifts.Add($Result.Message)  | Out-Null }
  }
  if (-not $Result.Ok) { $Ok.Value = $false }
}

# -----------------------------
# Catalog defaults + loader
# -----------------------------

function New-DefaultCatalog {
  [CmdletBinding()]
  param()

  $defaultProof = Join-Path $env:ProgramData 'WUfB-Proofing\proof.json'

  return [pscustomobject]@{
    UpdateSource = 'WUfB'
    WSUS = [pscustomobject]@{ WUServer = $null; WUStatusServer = $null }
    AllowMU = $true
    Deferrals = [pscustomobject]@{ FeatureDays = 30; QualityDays = 7 }
    TargetRelease = [pscustomobject]@{ Enable = $false; ProductVersion = 'Windows 11'; TargetReleaseVersionInfo = '24H2' }
    ActiveHours = [pscustomobject]@{ Enable = $true; Start = 8; End = 18 }
    DeliveryOptimization = [pscustomobject]@{ DownloadMode = 0 }
    Proof = [pscustomobject]@{ OutFile = $defaultProof }
  }
}

function Load-Catalog {
  [CmdletBinding()]
  param(
    [string]$CatalogPath,
    [string]$ConfigPath,
    [System.Collections.Generic.List[string]]$Notes
  )

  $default = New-DefaultCatalog

  if ($CatalogPath) {
    if (Test-Path -LiteralPath $CatalogPath) {
      try { $Notes.Add("Catalog loaded from CatalogPath.") | Out-Null; return (Get-Content -Raw -LiteralPath $CatalogPath | ConvertFrom-Json -ErrorAction Stop) }
      catch { $Notes.Add("CatalogPath JSON invalid. Using defaults. Error: $($_.Exception.Message)") | Out-Null; return $default }
    } else {
      $Notes.Add("CatalogPath not found. Using defaults.") | Out-Null
      return $default
    }
  }

  if ($ConfigPath -and (Test-Path -LiteralPath $ConfigPath)) {
    try {
      $cfg = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json -ErrorAction Stop
      $p = $null
      if ($cfg -and $cfg.WUfB -and $cfg.WUfB.CatalogPath) { $p = [string]$cfg.WUfB.CatalogPath }

      if ($p) {
        if (Test-Path -LiteralPath $p) {
          try { $Notes.Add("Catalog loaded from ConfigPath reference.") | Out-Null; return (Get-Content -Raw -LiteralPath $p | ConvertFrom-Json -ErrorAction Stop) }
          catch { $Notes.Add("Referenced catalog JSON invalid. Using defaults. Error: $($_.Exception.Message)") | Out-Null; return $default }
        } else {
          $Notes.Add("Referenced catalog path not found. Using defaults.") | Out-Null
          return $default
        }
      }
    } catch {
      $Notes.Add("ConfigPath JSON invalid. Using defaults. Error: $($_.Exception.Message)") | Out-Null
      return $default
    }
  }

  $Notes.Add("No catalog/config provided. Using defaults.") | Out-Null
  return $default
}

function Get-OsEvidence {
  [CmdletBinding()]
  param()

  $osKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $osProps = Get-ItemProperty -Path $osKey -ErrorAction SilentlyContinue

  return @{
    Product        = $osProps.ProductName
    DisplayVersion = $osProps.DisplayVersion
    Build          = $osProps.CurrentBuild
    UBR            = $osProps.UBR
  }
}

function Get-SafeProofPath {
  [CmdletBinding()]
  param([string]$Candidate)

  $fallback = Join-Path $env:ProgramData 'WUfB-Proofing\proof.json'
  if ([string]::IsNullOrWhiteSpace($Candidate)) { return $fallback }

  try {
    $full = [System.IO.Path]::GetFullPath($Candidate)
    $parent = Split-Path -Parent $full
    if ([string]::IsNullOrWhiteSpace($parent)) { return $fallback }
    return $full
  } catch {
    return $fallback
  }
}

function New-FirstErrorNote {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$ErrorRecord)

  $msg = $ErrorRecord.Exception.Message
  $line = $null
  try { $line = $ErrorRecord.InvocationInfo.ScriptLineNumber } catch { $line = $null }

  if ($line) { return ("Unhandled error: {0} (Line {1})" -f $msg, $line) }
  return ("Unhandled error: {0}" -f $msg)
}

# -----------------------------
# Main
# -----------------------------

$ok = $true
$eventLogStatus = "Not attempted"

$changes = New-Object 'System.Collections.Generic.List[string]'
$drifts  = New-Object 'System.Collections.Generic.List[string]'
$notes   = New-Object 'System.Collections.Generic.List[string]'
$ops     = New-Object 'System.Collections.Generic.List[object]'

$proofWrittenPath = $null
$outFile = Join-Path $env:ProgramData 'WUfB-Proofing\proof.json'

$Proof = [ordered]@{
  Time      = (Get-Date).ToString('s')
  Hostname  = $env:COMPUTERNAME
  OS        = (Get-OsEvidence)
  Catalog   = @{}
  Settings  = @{}
  Evidence  = @{}
  Actions   = @()
  Drift     = @()
  Notes     = @()
  Result    = @{
    Ok         = $true
    HasDrift   = $false
    Remediate  = [bool]$Remediate
    Strict     = [bool]$Strict
    Elevated   = $false
  }
}

$modeText = 'Audit'
if ($Remediate) { $modeText = 'Remediate' }

Write-Rule -Title ("WUfB Proofing - {0}" -f $env:COMPUTERNAME) -Color ([ConsoleColor]::DarkCyan)
Write-KV -Key 'Start' -Value (Get-Date).ToString()
Write-KV -Key 'Mode'  -Value $modeText
Write-Console ""

try {
  $eventSourceReady = Ensure-EventSource
  if (-not $eventSourceReady) { $notes.Add("Event source not ensured. EventLog write may fail.") | Out-Null }

  $isAdmin = Is-Admin
  $Proof.Result.Elevated = $isAdmin

  if (-not $isAdmin) {
    $notes.Add("Not elevated. Remediation may fail.") | Out-Null
    if ($Remediate) { $ok = $false }
  }

  $cat = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath -Notes $notes
  $Proof.Catalog = $cat

  $candidateOut = $null
  try { $candidateOut = [string]$cat.Proof.OutFile } catch { $candidateOut = $null }
  $outFile = Get-SafeProofPath -Candidate $candidateOut

  $wuPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
  $auPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
  $doPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'

  if (([string]$cat.UpdateSource) -eq 'WSUS') {
    $r = Set-REGDWORD -Path $auPol -Name 'UseWUServer' -Value 1 -Remediate:$Remediate
    Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

    if ([string]::IsNullOrWhiteSpace([string]$cat.WSUS.WUServer)) {
      $notes.Add("UpdateSource=WSUS but WSUS.WUServer is empty.") | Out-Null
      $ok = $false
    } else {
      $r = Set-REGSZ -Path $wuPol -Name 'WUServer' -Value ([string]$cat.WSUS.WUServer) -Remediate:$Remediate
      Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops
    }

    if ([string]::IsNullOrWhiteSpace([string]$cat.WSUS.WUStatusServer)) {
      $notes.Add("UpdateSource=WSUS but WSUS.WUStatusServer is empty.") | Out-Null
      $ok = $false
    } else {
      $r = Set-REGSZ -Path $wuPol -Name 'WUStatusServer' -Value ([string]$cat.WSUS.WUStatusServer) -Remediate:$Remediate
      Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops
    }
  } else {
    $r = Set-REGDWORD -Path $auPol -Name 'UseWUServer' -Value 0 -Remediate:$Remediate
    Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

    $r = Remove-REGValue -Path $wuPol -Name 'WUServer' -Remediate:$Remediate
    Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

    $r = Remove-REGValue -Path $wuPol -Name 'WUStatusServer' -Remediate:$Remediate
    Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops
  }

  $featureDays = 30
  $qualityDays = 7

  try { if ($null -ne $cat.Deferrals.FeatureDays) { $featureDays = [int]$cat.Deferrals.FeatureDays } } catch { $notes.Add("Deferrals.FeatureDays invalid. Using default 30.") | Out-Null; $featureDays = 30 }
  try { if ($null -ne $cat.Deferrals.QualityDays) { $qualityDays = [int]$cat.Deferrals.QualityDays } } catch { $notes.Add("Deferrals.QualityDays invalid. Using default 7.") | Out-Null; $qualityDays = 7 }

  if ($featureDays -lt 0 -or $featureDays -gt 365) { $notes.Add("Deferrals.FeatureDays out of range (0-365). Using default 30.") | Out-Null; $featureDays = 30 }
  if ($qualityDays -lt 0 -or $qualityDays -gt 35) { $notes.Add("Deferrals.QualityDays out of range (0-35). Using default 7.") | Out-Null; $qualityDays = 7 }

  $r = Set-REGDWORD -Path $wuPol -Name 'DeferFeatureUpdates' -Value 1 -Remediate:$Remediate
  Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

  $r = Set-REGDWORD -Path $wuPol -Name 'DeferFeatureUpdatesPeriodInDays' -Value $featureDays -Remediate:$Remediate
  Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

  $r = Set-REGDWORD -Path $wuPol -Name 'DeferQualityUpdates' -Value 1 -Remediate:$Remediate
  Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

  $r = Set-REGDWORD -Path $wuPol -Name 'DeferQualityUpdatesPeriodInDays' -Value $qualityDays -Remediate:$Remediate
  Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

  $trEnable = $false
  try { $trEnable = [bool]$cat.TargetRelease.Enable } catch { $trEnable = $false }

  if ($trEnable) {
    $prod = [string]$cat.TargetRelease.ProductVersion
    $info = [string]$cat.TargetRelease.TargetReleaseVersionInfo

    if ([string]::IsNullOrWhiteSpace($prod) -or [string]::IsNullOrWhiteSpace($info)) {
      $notes.Add("TargetRelease enabled but missing ProductVersion/TargetReleaseVersionInfo. Disabling pinning.") | Out-Null
      $trEnable = $false
    } else {
      $r = Set-REGDWORD -Path $wuPol -Name 'TargetReleaseVersion' -Value 1 -Remediate:$Remediate
      Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

      $r = Set-REGSZ -Path $wuPol -Name 'ProductVersion' -Value $prod -Remediate:$Remediate
      Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

      $r = Set-REGSZ -Path $wuPol -Name 'TargetReleaseVersionInfo' -Value $info -Remediate:$Remediate
      Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops
    }
  }

  if (-not $trEnable) {
    $r = Set-REGDWORD -Path $wuPol -Name 'TargetReleaseVersion' -Value 0 -Remediate:$Remediate
    Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

    $r = Remove-REGValue -Path $wuPol -Name 'ProductVersion' -Remediate:$Remediate
    Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

    $r = Remove-REGValue -Path $wuPol -Name 'TargetReleaseVersionInfo' -Remediate:$Remediate
    Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops
  }

  if ($null -ne $cat.DeliveryOptimization -and $null -ne $cat.DeliveryOptimization.DownloadMode) {
    try {
      $r = Set-REGDWORD -Path $doPol -Name 'DODownloadMode' -Value ([int]$cat.DeliveryOptimization.DownloadMode) -Remediate:$Remediate
      Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops
    } catch {
      $notes.Add("DeliveryOptimization.DownloadMode invalid. Skipped.") | Out-Null
    }
  }

  if ($null -ne $cat.ActiveHours -and $cat.ActiveHours.Enable -eq $true) {
    $Proof.Settings.ActiveHours = @{ Start = [int]$cat.ActiveHours.Start; End = [int]$cat.ActiveHours.End }
  }

  $Proof.Evidence.Registry = @{
    WindowsUpdatePolicyPath         = $wuPol
    AUPath                          = $auPol
    DeliveryOptimizationPath        = $doPol
    UseWUServer                     = (Get-REG -Path $auPol -Name 'UseWUServer')
    WUServer                        = (Get-REG -Path $wuPol -Name 'WUServer')
    WUStatusServer                  = (Get-REG -Path $wuPol -Name 'WUStatusServer')
    DeferFeatureUpdatesPeriodInDays = (Get-REG -Path $wuPol -Name 'DeferFeatureUpdatesPeriodInDays')
    DeferQualityUpdatesPeriodInDays = (Get-REG -Path $wuPol -Name 'DeferQualityUpdatesPeriodInDays')
    TargetReleaseVersion            = (Get-REG -Path $wuPol -Name 'TargetReleaseVersion')
    ProductVersion                  = (Get-REG -Path $wuPol -Name 'ProductVersion')
    TargetReleaseVersionInfo        = (Get-REG -Path $wuPol -Name 'TargetReleaseVersionInfo')
    DODownloadMode                  = (Get-REG -Path $doPol -Name 'DODownloadMode')
  }

  $hasDrift = ($drifts.Count -gt 0)
  $Proof.Result.HasDrift = $hasDrift
  $Proof.Result.Ok = $ok
  $Proof.Actions = @($changes.ToArray())
  $Proof.Drift   = @($drifts.ToArray())
  $Proof.Notes   = @($notes.ToArray())

  $proofWrittenPath = Save-JsonNoBom -Obj $Proof -Path $outFile
  $changes.Add("Proof JSON: $proofWrittenPath") | Out-Null

  $eventId = 4980
  $level   = 'Information'
  if (-not $ok) { $eventId = 4990; $level = 'Error' }
  elseif ($Strict -and $hasDrift) { $eventId = 4990; $level = 'Warning' }

  $eventMsg = "WUfB proof done. Changes=$($changes.Count) Drift=$($drifts.Count) Notes=$($notes.Count)"
  $written = Write-HealthEvent -Id $eventId -Msg $eventMsg -Level $level
  if ($written) { $eventLogStatus = "Written" } else { $eventLogStatus = "Not written (source/rights)" }

} catch {
  $ok = $false
  $notes.Add((New-FirstErrorNote -ErrorRecord $_)) | Out-Null
  $eventLogStatus = "Not written (error)"

  try {
    $fallback = Join-Path $env:ProgramData 'WUfB-Proofing\proof-error.json'
    $proofWrittenPath = Save-JsonNoBom -Obj $Proof -Path $fallback
  } catch {}
} finally {
  $hasDriftFinal = ($drifts.Count -gt 0)

  $resultLabel = 'OK'
  if (-not $ok) { $resultLabel = 'ERROR' }
  elseif ($Strict -and $hasDriftFinal) { $resultLabel = 'WARNING' }
  elseif (-not $Remediate -and $hasDriftFinal) { $resultLabel = 'DRIFT' }

  $proofPathToShow = $outFile
  if ($proofWrittenPath) { $proofPathToShow = $proofWrittenPath }

  $summary = @{
    Result         = $resultLabel
    Elevated       = $Proof.Result.Elevated
    Remediate      = [bool]$Remediate
    Strict         = [bool]$Strict
    ChangesCount   = $changes.Count
    DriftCount     = $drifts.Count
    NotesCount     = $notes.Count
    EventLogStatus = $eventLogStatus
    ProofPath      = $proofPathToShow
  }

  Write-ConsoleSummary -Summary $summary -Changes $changes.ToArray() -Drift $drifts.ToArray() -Notes $notes.ToArray()

  if ($PassThru) {
    [pscustomobject]@{
      Time         = $Proof.Time
      Hostname     = $Proof.Hostname
      Result       = $resultLabel
      Elevated     = $Proof.Result.Elevated
      Remediate    = [bool]$Remediate
      Strict       = [bool]$Strict
      HasDrift     = [bool]$hasDriftFinal
      DriftCount   = $drifts.Count
      ChangesCount = $changes.Count
      NotesCount   = $notes.Count
      ProofPath    = $proofPathToShow
      EventLog     = $eventLogStatus
      Drift        = $drifts.ToArray()
      Changes      = $changes.ToArray()
      Notes        = $notes.ToArray()
      Evidence     = $Proof.Evidence
      Catalog      = $Proof.Catalog
      Operations   = $ops.ToArray()
    }
  }

  if (-not $ok) { exit 1 }
  if ($Strict -and $hasDriftFinal) { exit 2 }
}
