#requires -version 5.1
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
  - Remediation mode (-Mode Remediate): Applies idempotent registry changes to match the catalog and reports changes.

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

.PARAMETER Strict
  Changes result handling when drift is detected.
  - Without -Strict: drift is reported as DRIFT (useful for audit reporting without failing a pipeline).
  - With -Strict: drift is treated as WARNING and the script exits with a non-zero status code to signal attention.

.PARAMETER PassThru
  Emits one structured result object to the pipeline at the end of the run.
  The object includes the overall result, counts, proof path, evidence snapshot, the loaded catalog, and lists of
  drift/changes/notes.


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.

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
  .\scripts\05-WUFB-Proofing.ps1 -CatalogPath .\examples\configs\wufb-proofing.json

.EXAMPLE
  # Audit using a config JSON that references a catalog path
  .\05-WUFB-Proofing.ps1 -ConfigPath $ConfigPath

.EXAMPLE
  # Remediate and show structured output for further processing
  .\scripts\05-WUFB-Proofing.ps1 -CatalogPath .\examples\configs\wufb-proofing.json -Mode Remediate -PassThru

.EXAMPLE
  # Integrate in reporting pipelines (one object only)
  .\05-WUFB-Proofing.ps1 -PassThru | ConvertTo-Json -Depth 6

.EXAMPLE
  # Export a single-run result to CSV (flattening may be required for nested properties)
  .\05-WUFB-Proofing.ps1 -PassThru | Select-Object Time,Hostname,Result,HasDrift,DriftCount,ChangesCount,ProofPath | Export-Csv -NoTypeInformation -Path $OutputPath

.NOTES
  Requires local administrator privileges only for operations that write to HKLM policy registry keys and for
  registering/writing to a Windows Event Log source (if enabled by the script).
  If not elevated, the script can still audit but remediation may fail and is reported accordingly.

  Exit codes:
  - 0 = OK, 2 = WARN, 1 = FAIL.

  Proof output:
  - A proof JSON is written even in error cases (best effort), using a safe fallback path when necessary.
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$CatalogPath,
  [string]$ConfigPath,
  [switch]$Strict,
  [switch]$PassThru

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '05-WUFB-Proofing.ps1' -BoundParameters $PSBoundParameters `
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
  $result = Get-V2ResultObject -ScriptName '05-WUFB-Proofing.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$script:Findings = Get-FindingsList

# -----------------------------
# Console helpers (no pipeline)
# -----------------------------





# -----------------------------
# Event log (best-effort)
# -----------------------------


# -----------------------------
# Security / registry / file helpers
# -----------------------------

# Test-IsAdmin imported from lib/Common.psm1

# Ensure-Key replaced by Ensure-RegistryKey from lib/Registry.psm1

function Get-REG {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name
  )
  try { (Get-ItemProperty -Path $Path -ErrorAction Stop).$Name } catch { $null }
}

function Set-WufbDword {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][int]$Value,
    [switch]$Remediate
  )

  $cur = Get-REG -Path $Path -Name $Name

  if ($cur -eq $Value) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$false; Message=$null; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='None' }
  }

  if (-not $Remediate) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="$Path\$Name drift ($cur != $Value)"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Detect' }
  }

  if (-not $PSCmdlet.ShouldProcess("$Path\$Name", "Set DWORD value")) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="Skipped setting $Path\$Name due to confirmation/WhatIf."; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Skipped' }
  }

  try {
    Ensure-RegistryKey -Path $Path
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
    return [pscustomobject]@{ Ok=$true; Changed=$true; Drift=$false; Message="Set $Path\$Name=$Value"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='SetDword' }
  } catch {
    return [pscustomobject]@{ Ok=$false; Changed=$false; Drift=$false; Message="Set $Path\$Name failed: $($_.Exception.Message)"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Error' }
  }
}

function Set-REGSZ {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Value,
    [switch]$Remediate
  )

  $cur = Get-REG -Path $Path -Name $Name

  if ($cur -eq $Value) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$false; Message=$null; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='None' }
  }

  if (-not $Remediate) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="$Path\$Name drift ($cur != '$Value')"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Detect' }
  }

  if (-not $PSCmdlet.ShouldProcess("$Path\$Name", "Set string value")) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="Skipped setting $Path\$Name due to confirmation/WhatIf."; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Skipped' }
  }

  try {
    Ensure-RegistryKey -Path $Path
    New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force | Out-Null
    return [pscustomobject]@{ Ok=$true; Changed=$true; Drift=$false; Message="Set $Path\$Name='$Value'"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='SetString' }
  } catch {
    return [pscustomobject]@{ Ok=$false; Changed=$false; Drift=$false; Message="Set $Path\$Name failed: $($_.Exception.Message)"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Error' }
  }
}

function Remove-REGValue {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [switch]$Remediate
  )

  $cur = Get-REG -Path $Path -Name $Name

  if ($null -eq $cur) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$false; Message=$null; Path=$Path; Name=$Name; Current=$cur; Desired=$null; Action='None' }
  }

  if (-not $Remediate) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="$Path\$Name should be absent, but is present ($cur)"; Path=$Path; Name=$Name; Current=$cur; Desired=$null; Action='Detect' }
  }

  if (-not $PSCmdlet.ShouldProcess("$Path\$Name", "Remove registry value")) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="Skipped removing $Path\$Name due to confirmation/WhatIf."; Path=$Path; Name=$Name; Current=$cur; Desired=$null; Action='Skipped' }
  }

  try {
    Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
    return [pscustomobject]@{ Ok=$true; Changed=$true; Drift=$false; Message="Removed $Path\$Name"; Path=$Path; Name=$Name; Current=$cur; Desired=$null; Action='RemoveValue' }
  } catch {
    return [pscustomobject]@{ Ok=$false; Changed=$false; Drift=$false; Message="Remove $Path\$Name failed: $($_.Exception.Message)"; Path=$Path; Name=$Name; Current=$cur; Desired=$null; Action='Error' }
  }
}

# Save-JsonNoBom: replaced by canonical Save-Json from lib/Serialization.psm1

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

function Get-WufbTrustedDataRoot {
  $root = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { $root = [IO.Path]::GetTempPath() }
  if ([string]::IsNullOrWhiteSpace($root)) { throw 'CommonApplicationData could not be resolved.' }
  return [IO.Path]::GetFullPath($root)
}

function Get-DefaultCatalog {
  [CmdletBinding()]
  param()

  $defaultProof = Join-Path (Get-WufbTrustedDataRoot) 'WUfB-Proofing\proof.json'

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

  $default = Get-DefaultCatalog

  if ($CatalogPath) {
    if (Test-Path -LiteralPath $CatalogPath) {
      try { $Notes.Add("Catalog loaded from CatalogPath.") | Out-Null; return (Get-BoundedUtf8FileContent -Path $CatalogPath -MaximumBytes 1048576 | ConvertFrom-Json -ErrorAction Stop) }
      catch { $Notes.Add("CatalogPath JSON invalid. Using defaults. Error: $($_.Exception.Message)") | Out-Null; return $default }
    } else {
      $Notes.Add("CatalogPath not found. Using defaults.") | Out-Null
      return $default
    }
  }

  if ($ConfigPath -and (Test-Path -LiteralPath $ConfigPath)) {
    try {
      $cfg = Get-BoundedUtf8FileContent -Path $ConfigPath -MaximumBytes 1048576 | ConvertFrom-Json -ErrorAction Stop
      $p = $null
      if ($cfg -and $cfg.WUfB -and $cfg.WUfB.CatalogPath) { $p = [string]$cfg.WUfB.CatalogPath }

      if ($p) {
        if (Test-Path -LiteralPath $p) {
          try { $Notes.Add("Catalog loaded from ConfigPath reference.") | Out-Null; return (Get-BoundedUtf8FileContent -Path $p -MaximumBytes 1048576 | ConvertFrom-Json -ErrorAction Stop) }
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

  $fallback = Join-Path (Get-WufbTrustedDataRoot) 'WUfB-Proofing\proof.json'
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

function Get-FirstErrorNote {
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
$outFile = Join-Path (Get-WufbTrustedDataRoot) 'WUfB-Proofing\proof.json'

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

Write-DecorativeRule -Title ("WUfB Proofing - {0}" -f $env:COMPUTERNAME) -Color 'Header'
Write-KeyValue -Key 'Start' -Value (Get-Date).ToString()
Write-KeyValue -Key 'Mode'  -Value $modeText
Write-UiLine ""

try {
  if (-not (Ensure-EventSource)) {
    Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
    $notes.Add("Event source not ensured. EventLog write may fail.") | Out-Null
  }

  $isAdmin = Test-IsAdmin
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
    $r = Set-WufbDword -Path $auPol -Name 'UseWUServer' -Value 1 -Remediate:$Remediate
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
    $r = Set-WufbDword -Path $auPol -Name 'UseWUServer' -Value 0 -Remediate:$Remediate
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

  $r = Set-WufbDword -Path $wuPol -Name 'DeferFeatureUpdates' -Value 1 -Remediate:$Remediate
  Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

  $r = Set-WufbDword -Path $wuPol -Name 'DeferFeatureUpdatesPeriodInDays' -Value $featureDays -Remediate:$Remediate
  Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

  $r = Set-WufbDword -Path $wuPol -Name 'DeferQualityUpdates' -Value 1 -Remediate:$Remediate
  Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

  $r = Set-WufbDword -Path $wuPol -Name 'DeferQualityUpdatesPeriodInDays' -Value $qualityDays -Remediate:$Remediate
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
      $r = Set-WufbDword -Path $wuPol -Name 'TargetReleaseVersion' -Value 1 -Remediate:$Remediate
      Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

      $r = Set-REGSZ -Path $wuPol -Name 'ProductVersion' -Value $prod -Remediate:$Remediate
      Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

      $r = Set-REGSZ -Path $wuPol -Name 'TargetReleaseVersionInfo' -Value $info -Remediate:$Remediate
      Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops
    }
  }

  if (-not $trEnable) {
    $r = Set-WufbDword -Path $wuPol -Name 'TargetReleaseVersion' -Value 0 -Remediate:$Remediate
    Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

    $r = Remove-REGValue -Path $wuPol -Name 'ProductVersion' -Remediate:$Remediate
    Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops

    $r = Remove-REGValue -Path $wuPol -Name 'TargetReleaseVersionInfo' -Remediate:$Remediate
    Add-Result -Result $r -Changes $changes -Drifts $drifts -Ok ([ref]$ok) -Ops $ops
  }

  if ($null -ne $cat.DeliveryOptimization -and $null -ne $cat.DeliveryOptimization.DownloadMode) {
    try {
      $r = Set-WufbDword -Path $doPol -Name 'DODownloadMode' -Value ([int]$cat.DeliveryOptimization.DownloadMode) -Remediate:$Remediate
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

  Save-Json -InputObject $Proof -Path $outFile -Depth 12 -NoBom
  $proofWrittenPath = $outFile
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
  $notes.Add((Get-FirstErrorNote -ErrorRecord $_)) | Out-Null
  $eventLogStatus = "Not written (error)"

  try {
    $fallback = Join-Path (Get-WufbTrustedDataRoot) 'WUfB-Proofing\proof-error.json'
    Save-Json -InputObject $Proof -Path $fallback -Depth 12 -NoBom
    $proofWrittenPath = $fallback
  } catch {
    Write-Verbose ("Fallback WUfB proof save failed: {0}" -f $_.Exception.Message)
  }
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

  $summaryObj = [pscustomobject]$summary
  if (-not $summaryObj.PSObject.Properties['ComputerName']) {
    $summaryObj | Add-Member -NotePropertyName ComputerName -NotePropertyValue $env:COMPUTERNAME
  }
  Write-ConsoleSummary -Summary $summaryObj -Findings ([System.Collections.ArrayList]::new()) `
    -CustomFields ([ordered]@{
      Result     = $summary.Result
      Elevated   = $summary.Elevated
      Remediate  = $summary.Remediate
      Strict     = $summary.Strict
      Changes    = $summary.ChangesCount
      Drift      = $summary.DriftCount
      Notes      = $summary.NotesCount
      EventLog   = $summary.EventLogStatus
      'Proof JSON' = $summary.ProofPath
    })
  $changesArr = $changes.ToArray()
  $driftsArr  = $drifts.ToArray()
  $notesArr   = $notes.ToArray()
  if ($changesArr -and $changesArr.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine "Changes:" -ForegroundColor ([ConsoleColor]::Green)
    foreach ($c in $changesArr) { Write-UiLine ("- {0}" -f $c) -ForegroundColor ([ConsoleColor]::Gray) }
  }
  if ($driftsArr -and $driftsArr.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine "Drift:" -ForegroundColor ([ConsoleColor]::Yellow)
    foreach ($d in $driftsArr) { Write-UiLine ("- {0}" -f $d) -ForegroundColor ([ConsoleColor]::Gray) }
  }
  if ($notesArr -and $notesArr.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine "Notes:" -ForegroundColor ([ConsoleColor]::Cyan)
    foreach ($n in $notesArr) { Write-UiLine ("- {0}" -f $n) -ForegroundColor ([ConsoleColor]::Gray) }
  }

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

}

foreach ($d in @($drifts)) {
  $code = 'WUFB-Drift'
  $sev = 'Medium'
  if ($d -match 'WSUS')           { $code = 'WUFB-WsusDrift' }
  if ($d -match 'Deferral')       { $code = 'WUFB-DeferralDrift' }
  if ($d -match 'TargetRelease')  { $code = 'WUFB-TargetReleaseDrift' }
  if ($d -match 'DeliveryOpt')    { $code = 'WUFB-DeliveryOptDrift' }
  if ($d -match 'Failed')         { $sev = 'High' }
  Add-Finding -FindingList $script:Findings -Code $code -Severity $sev -Message $d
}

# V2 output contract
$resultToken = if (-not $ok) { 'FAIL' } elseif ($hasDriftFinal) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '05-WUFB-Proofing.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary ([pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Ok = $ok; HasDrift = $hasDriftFinal; Timestamp = Get-Date }) -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
