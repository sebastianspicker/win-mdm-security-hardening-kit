#requires -version 5.1
<#
.SYNOPSIS
  Audits Windows hardware security posture (TPM, Secure Boot, BitLocker, BIOS) and evaluates it against a simple baseline catalog.

.DESCRIPTION
  This script performs a local hardware security audit and produces:
  - A single structured result object on the success output stream (pipeline-friendly).
  - A human-readable, colorized console summary (written via Write-UiLine/Write-Information only).
  - A JSON “proof” file containing the full structured result.
  - A Windows Event Log entry in the Application log for monitoring/alerting.

  The baseline (expected values) is taken from a "catalog" JSON. If no catalog is provided or it cannot be loaded,
  built-in defaults are used automatically.

  Checks performed:
  - TPM:
    - Presence and basic identity (e.g., SpecVersion, Manufacturer)
    - Status: Owned, Enabled, Activated, Ready (queried via TPM provider methods where available)
    - Optional hint whether a firmware TPM is used (only if the property exists on the platform)
  - Secure Boot:
    - Determines if Secure Boot is enabled
  - BitLocker:
    - Determines if the OS volume is protected (ProtectionStatus)
    - Captures additional diagnostics (encryption percentage, volume status, method) for troubleshooting
  - BIOS:
    - Captures basic BIOS inventory fields (serial, version, vendor, release date)

.PARAMETER CatalogPath
  Optional path to a compliance catalog JSON file.
  If provided, it is the first source used for baseline settings.

  Expected catalog schema (example):
  {
    "TPM": {
      "MinVersion": "2.0",
      "OwnerRequired": true,
      "PCRsRequired": [7],
      "AllowFirmware": false,
      "BitLockerRequired": true,
      "SecureBootRequired": true
    },
    "Proof": {
      "OutFile": null
    }
  }

.PARAMETER ConfigPath
  Optional path to a configuration JSON file.
  If present and readable, the script looks for:
    Hardware.CatalogPath
  and uses that catalog if found.

  This provides a central indirection so that the catalog location can be controlled without changing the script.

.PARAMETER Strict
  When set, any detected drift forces the script to write a Warning event (EventId 4900).
  Without -Strict, a fully compliant result writes an Information event (EventId 4890) and a non-compliant result writes a Warning event (EventId 4900).


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER PassThru
  Emit structured v2 result object to pipeline.

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
  System.Management.Automation.PSCustomObject

  The script writes exactly one object to the pipeline, with the following top-level properties:
  - Time     (string): Timestamp of the run.
  - Hostname (string): Computer name.
  - Context  (object): Execution context (user, admin status, PowerShell version, etc.).
  - Results  (object): Per-check results (TPM/SecureBoot/BitLocker/BIOS) plus:
      - OverallOk (bool): True when all required baseline checks pass.
      - Drifts    (string[]): Human-readable list of failed checks / deviations.
      - Notes     (string[]): Additional context (e.g., checks not implemented or data not available).
  - Errors   (string[]): Reserved for captured internal errors (when used).

  Example pipeline usage:
    $r = .\15-HardwareTPM-Audit.ps1
    $r.Results.OverallOk
    $r | ConvertTo-Json -Depth 10
    $r.Results.Drifts | Where-Object { $_ -match 'BitLocker' }

.NOTES
  Event logging:
  - The script writes to the Application log using a dedicated Source name.
  - If the Source cannot be created/used (for example due to permissions), the script falls back to writing the event message to the console.

  JSON proof file:
  - The proof file path is taken from the catalog (Proof.OutFile). If missing/unusable, a built-in default path is used.
  - The directory is created automatically if needed.

  Platform variability:
  - Some TPM provider properties (e.g., PCRBanks, firmware hint flags) are not guaranteed to exist on all systems.
    The script treats these as optional and records Notes when a requirement cannot be evaluated.

.EXAMPLE
  PS> .\15-HardwareTPM-Audit.ps1

  Runs with built-in default baseline settings and writes:
  - One result object to the pipeline
  - A console summary
  - A proof JSON file
  - An event log entry

.EXAMPLE
  PS> .\15-HardwareTPM-Audit.ps1 -CatalogPath $CatalogPath

  Runs using the specified baseline catalog JSON.

.EXAMPLE
  PS> .\15-HardwareTPM-Audit.ps1 -ConfigPath $ConfigPath

  Runs using the catalog referenced by Hardware.CatalogPath inside the config JSON (if present),
  otherwise falls back to built-in defaults.

.EXAMPLE
  PS> .\15-HardwareTPM-Audit.ps1 -Strict

  Runs with stricter event semantics: any drift results in a Warning event (EventId 4900).

.EXAMPLE
  PS> $result = .\15-HardwareTPM-Audit.ps1
  PS> if (-not $result.Results.OverallOk) { $result.Results.Drifts }

  Integrates the script into a larger automation pipeline without parsing console text.

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$CatalogPath,
  [switch]$Strict,
  [string]$ConfigPath

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '15-HardwareTPM-Audit.ps1' -BoundParameters $PSBoundParameters `
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
  $result = Get-V2ResultObject -ScriptName '15-HardwareTPM-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$script:Findings = Get-FindingsList

# Anonymized defaults
$EventLogName   = 'Application'
$EventSource    = 'HardwareTPM-Audit'
$DefaultOutFile = Join-Path ([System.IO.Path]::GetTempPath()) 'HardwareCompliance.json'

# -----------------------------
# Helpers (no pipeline formatting)
# -----------------------------


# Save-Json: using canonical Save-Json from lib/Serialization.psm1

function Add-ListItem {
  param([Parameter(Mandatory=$true)][ref]$List,[Parameter(Mandatory=$true)][string]$Text)
  if ($Text) { [void]$List.Value.Add($Text) }
}

function ConvertFrom-JsonSafe {
  param([Parameter(Mandatory=$true)][string]$JsonText)
  try { return ($JsonText | ConvertFrom-Json) } catch { return $null }
}

function Get-DefaultCatalog {
  # Always available defaults (no JSON dependency).
  return (New-Object PSObject -Property @{
    TPM = (New-Object PSObject -Property @{
      MinVersion         = '2.0'
      OwnerRequired      = $true
      PCRsRequired       = @(7)
      AllowFirmware      = $false
      BitLockerRequired  = $true
      SecureBootRequired = $true
    })
    Proof = (New-Object PSObject -Property @{
      OutFile = $DefaultOutFile
    })
  })
}

function Merge-CatalogWithDefaults {
  param([Parameter(Mandatory=$true)]$Catalog,[Parameter(Mandatory=$true)]$Defaults)

  if (-not $Catalog) { return $Defaults }

  if (-not $Catalog.TPM)   { $Catalog | Add-Member -NotePropertyName TPM   -NotePropertyValue (New-Object PSObject) }
  if (-not $Catalog.Proof) { $Catalog | Add-Member -NotePropertyName Proof -NotePropertyValue (New-Object PSObject) }

  if (-not $Catalog.TPM.MinVersion)              { $Catalog.TPM | Add-Member -NotePropertyName MinVersion         -NotePropertyValue $Defaults.TPM.MinVersion }
  if ($null -eq $Catalog.TPM.OwnerRequired)      { $Catalog.TPM | Add-Member -NotePropertyName OwnerRequired      -NotePropertyValue $Defaults.TPM.OwnerRequired }
  if ($null -eq $Catalog.TPM.PCRsRequired)       { $Catalog.TPM | Add-Member -NotePropertyName PCRsRequired       -NotePropertyValue $Defaults.TPM.PCRsRequired }
  if ($null -eq $Catalog.TPM.AllowFirmware)      { $Catalog.TPM | Add-Member -NotePropertyName AllowFirmware      -NotePropertyValue $Defaults.TPM.AllowFirmware }
  if ($null -eq $Catalog.TPM.BitLockerRequired)  { $Catalog.TPM | Add-Member -NotePropertyName BitLockerRequired  -NotePropertyValue $Defaults.TPM.BitLockerRequired }
  if ($null -eq $Catalog.TPM.SecureBootRequired) { $Catalog.TPM | Add-Member -NotePropertyName SecureBootRequired -NotePropertyValue $Defaults.TPM.SecureBootRequired }

  if (-not $Catalog.Proof.OutFile) { $Catalog.Proof | Add-Member -NotePropertyName OutFile -NotePropertyValue $Defaults.Proof.OutFile }

  return $Catalog
}

function Load-Catalog {
  param([string]$CatalogPath,[string]$ConfigPath)

  $defaults = Get-DefaultCatalog

  # 1) Explicit catalog
  if ($CatalogPath -and (Test-Path -LiteralPath $CatalogPath)) {
    $raw = Get-BoundedUtf8FileContent -Path $CatalogPath -MaximumBytes 1048576 -ErrorAction SilentlyContinue
    if ($raw) {
      $obj = ConvertFrom-JsonSafe -JsonText $raw
      if ($obj) { return (Merge-CatalogWithDefaults -Catalog $obj -Defaults $defaults) }
    }
  }

  # 2) Config -> Hardware.CatalogPath
  if ($ConfigPath -and (Test-Path -LiteralPath $ConfigPath)) {
    $rawCfg = Get-BoundedUtf8FileContent -Path $ConfigPath -MaximumBytes 1048576 -ErrorAction SilentlyContinue
    if ($rawCfg) {
      $cfg = ConvertFrom-JsonSafe -JsonText $rawCfg
      if ($cfg -and $cfg.Hardware -and $cfg.Hardware.CatalogPath) {
        $p = [string]$cfg.Hardware.CatalogPath
        if ($p -and (Test-Path -LiteralPath $p)) {
          $raw2 = Get-BoundedUtf8FileContent -Path $p -MaximumBytes 1048576 -ErrorAction SilentlyContinue
          if ($raw2) {
            $obj2 = ConvertFrom-JsonSafe -JsonText $raw2
            if ($obj2) { return (Merge-CatalogWithDefaults -Catalog $obj2 -Defaults $defaults) }
          }
        }
      }
    }
  }

  return $defaults
}

function Test-TpmMinVersion {
  param([Parameter(Mandatory=$true)][string]$SpecVersion,[Parameter(Mandatory=$true)][string]$MinVersion)
  # SpecVersion may contain multiple values like "2.0,1.2".
  return ($SpecVersion -match "(^|,)\s*$([regex]::Escape($MinVersion))(\s*|,|$)")
}

function Invoke-TpmBoolMethod {
  param(
    [Parameter(Mandatory=$true)]$Tpm,
    [Parameter(Mandatory=$true)][string]$MethodName,
    [Parameter(Mandatory=$true)][string]$ReturnPropertyName
  )
  try {
    $r = Invoke-CimMethod -InputObject $Tpm -MethodName $MethodName -ErrorAction Stop
    if ($r -and ($r.PSObject.Properties.Name -contains $ReturnPropertyName)) { return [bool]$r.$ReturnPropertyName }
    return $null
  } catch {
    return $null
  }
}

function Get-CimPropValue {
  param([Parameter(Mandatory=$true)]$Object,[Parameter(Mandatory=$true)][string]$Name)
  if ($null -eq $Object) { return $null }
  if ($Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
  return $null
}

# -----------------------------
# Main
# -----------------------------

$isAdmin       = Test-IsAdmin
$eventSourceOk = $true
if (-not (Ensure-EventSource -Source $EventSource -LogName $EventLogName)) {
  $eventSourceOk = $false
  Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
}

$drifts = New-Object System.Collections.Generic.List[string]
$notes  = New-Object System.Collections.Generic.List[string]
$errors = New-Object System.Collections.Generic.List[string]
$ok     = $true
$fatalComplianceFailure = $false
$eventWriteSucceeded = $null

$proof = [ordered]@{
  Time     = (Get-Date).ToString('s')
  Hostname = $env:COMPUTERNAME
  Context  = [ordered]@{
    UserName      = $env:USERNAME
    IsAdmin       = $isAdmin
    PSVersion     = $PSVersionTable.PSVersion.ToString()
    EventSourceOk = $eventSourceOk
    CatalogPath   = $(if ($CatalogPath) { $CatalogPath } else { $null })
    ConfigPath    = $(if ($ConfigPath) { $ConfigPath } else { $null })
  }
  Results  = [ordered]@{}
  Errors   = @()
}

try {
  $cat = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath

  $outFile = $DefaultOutFile
  if ($cat -and $cat.Proof -and $cat.Proof.OutFile) { $outFile = [string]$cat.Proof.OutFile }
  if (-not $outFile) { $outFile = $DefaultOutFile }

  # -----------------------------
  # TPM
  # -----------------------------
  $tpm = $null
  try {
    $tpm = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName "Win32_Tpm" -ErrorAction Stop
  } catch {
    Add-ListItem -List ([ref]$notes) -Text ("TPM query failed: " + $_.Exception.Message)
  }

  $proof.Results.TPM = [ordered]@{
    Present      = [bool]$tpm
    SpecVersion  = $null
    Manufacturer = $null
    IsOwned      = $null
    Enabled      = $null
    Activated    = $null
    Ready        = $null
    FirmwareHint = $null
    PCRBanks     = $null
  }

  if (-not $tpm) {
    $ok = $false
    $fatalComplianceFailure = $true
    Add-ListItem -List ([ref]$drifts) -Text "TPM not present or not accessible"
  } else {
    $proof.Results.TPM.SpecVersion  = [string](Get-CimPropValue -Object $tpm -Name 'SpecVersion')
    $proof.Results.TPM.Manufacturer = Get-CimPropValue -Object $tpm -Name 'ManufacturerID'
    $proof.Results.TPM.PCRBanks     = Get-CimPropValue -Object $tpm -Name 'PCRBanks'
    $proof.Results.TPM.FirmwareHint = $(if ($tpm.PSObject.Properties.Name -contains 'IsFirmware') { [bool]$tpm.IsFirmware } else { $null })

    $proof.Results.TPM.IsOwned   = Invoke-TpmBoolMethod -Tpm $tpm -MethodName "IsOwned"     -ReturnPropertyName "IsOwned"
    $proof.Results.TPM.Enabled   = Invoke-TpmBoolMethod -Tpm $tpm -MethodName "IsEnabled"   -ReturnPropertyName "IsEnabled"
    $proof.Results.TPM.Activated = Invoke-TpmBoolMethod -Tpm $tpm -MethodName "IsActivated" -ReturnPropertyName "IsActivated"
    $proof.Results.TPM.Ready     = Invoke-TpmBoolMethod -Tpm $tpm -MethodName "IsReady"     -ReturnPropertyName "IsReady"

    if ($cat.TPM.MinVersion -and $proof.Results.TPM.SpecVersion) {
      if (-not (Test-TpmMinVersion -SpecVersion $proof.Results.TPM.SpecVersion -MinVersion ([string]$cat.TPM.MinVersion))) {
        $ok = $false
        Add-ListItem -List ([ref]$drifts) -Text ("TPM SpecVersion '{0}' does not satisfy MinVersion '{1}'" -f $proof.Results.TPM.SpecVersion, [string]$cat.TPM.MinVersion)
      }
    }

    if ($cat.TPM.OwnerRequired -and ($proof.Results.TPM.IsOwned -ne $true)) {
      $ok = $false
      Add-ListItem -List ([ref]$drifts) -Text "TPM not owned"
    }

    if ($proof.Results.TPM.Enabled -eq $false) {
      $ok = $false
      Add-ListItem -List ([ref]$drifts) -Text "TPM not enabled"
    }

    if ($proof.Results.TPM.Activated -eq $false) {
      $ok = $false
      Add-ListItem -List ([ref]$drifts) -Text "TPM not activated"
    }

    if ($proof.Results.TPM.Ready -eq $false) {
      $ok = $false
      Add-ListItem -List ([ref]$drifts) -Text "TPM not ready"
    }

    if (($cat.TPM.AllowFirmware -eq $false) -and ($proof.Results.TPM.FirmwareHint -eq $true)) {
      $ok = $false
      Add-ListItem -List ([ref]$drifts) -Text "Firmware TPM found; HW TPM required by catalog"
    }

    if ($cat.TPM.PCRsRequired) {
      Add-ListItem -List ([ref]$notes) -Text "PCR compliance not implemented: PCRBanks (if available) reports hash banks, not PCR indices."
    }
  }

  # -----------------------------
  # Secure Boot
  # -----------------------------
  $sb = $false
  try { $sb = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { Add-ListItem -List ([ref]$notes) -Text ("Confirm-SecureBootUEFI failed: " + $_.Exception.Message) }
  $proof.Results.SecureBoot = $sb

  if ($cat.TPM.SecureBootRequired -and -not $sb) {
    $ok = $false
    Add-ListItem -List ([ref]$drifts) -Text "Secure Boot not enabled"
  }

  # -----------------------------
  # BitLocker
  # -----------------------------
  $bitOsProtected = $false
  $volsOut        = @()
  $osVolDiag      = $null

  try {
    $drvs = Get-BitLockerVolume -ErrorAction Stop
    foreach ($d in $drvs) {
      if ($d.VolumeType -eq "OperatingSystem") {
        $bitOsProtected = ($d.ProtectionStatus -eq 1)
        $osVolDiag = [pscustomobject]@{
          MountPoint           = $d.MountPoint
          ProtectionStatus     = $d.ProtectionStatus
          VolumeStatus         = $d.VolumeStatus
          EncryptionPercentage = $d.EncryptionPercentage
          EncryptionMethod     = $d.EncryptionMethod
        }
      }

      $volsOut += [pscustomobject]@{
        MountPoint           = $d.MountPoint
        VolumeType           = $d.VolumeType
        ProtectionStatus     = $d.ProtectionStatus
        VolumeStatus         = $d.VolumeStatus
        EncryptionPercentage = $d.EncryptionPercentage
        EncryptionMethod     = $d.EncryptionMethod
      }
    }
  } catch {
    Add-ListItem -List ([ref]$notes) -Text ("Get-BitLockerVolume failed: " + $_.Exception.Message)
  }

  $proof.Results.BitLocker            = $volsOut
  $proof.Results.BitLockerOsProtected = $bitOsProtected
  $proof.Results.BitLockerOsVolume    = $osVolDiag

  if ($cat.TPM.BitLockerRequired -and -not $bitOsProtected) {
    $ok = $false
    Add-ListItem -List ([ref]$drifts) -Text "BitLocker not active on OS volume"
    if ($osVolDiag) {
      Add-ListItem -List ([ref]$notes) -Text ("BitLocker OS diagnostics: VolumeStatus={0}, EncryptionPercentage={1}, ProtectionStatus={2}" -f $osVolDiag.VolumeStatus, $osVolDiag.EncryptionPercentage, $osVolDiag.ProtectionStatus)
    }
  }

  # -----------------------------
  # BIOS
  # -----------------------------
  try {
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $proof.Results.BIOS = [ordered]@{
      SerialNumber      = $bios.SerialNumber
      SMBIOSBIOSVersion = $bios.SMBIOSBIOSVersion
      Manufacturer      = $bios.Manufacturer
      Name              = $bios.Name
      ReleaseDate       = $bios.ReleaseDate
    }
  } catch {
    Add-ListItem -List ([ref]$notes) -Text ("BIOS query failed: " + $_.Exception.Message)
    $proof.Results.BIOS = $null
  }

  # Finalize
  $proof.Results.OverallOk = $ok
  $proof.Results.Drifts    = $drifts.ToArray()
  $proof.Results.Notes     = $notes.ToArray()
  $proof.Errors            = $errors.ToArray()

  Save-Json -InputObject $proof -Path $outFile -Depth 10

  # Event message (keep compact)
  $lines = @()
  if ($drifts.Count -gt 0) { $lines += ("Drift: " + ($drifts.ToArray() -join " | ")) }
  if ($notes.Count  -gt 0) { $lines += ("Notes: " + ($notes.ToArray()  -join " | ")) }
  if ($lines.Count -eq 0)  { $lines += "TPM/BitLocker/SecureBoot baseline compliant." }
  $msg = $lines -join "`r`n"

  $eventId = 4890
  $level   = 'Information'
  if (-not $ok) { $eventId = 4900; $level = 'Warning' }
  if ($Strict -and $drifts.Count -gt 0) { $eventId = 4900; $level = 'Warning' }

  $eventWriteSucceeded = Write-HealthEvent -Id $eventId -Message $msg -Level $level -Source $EventSource -LogName $EventLogName
  if ($eventWriteSucceeded -eq $false) {
    Add-ListItem -List ([ref]$notes) -Text 'Required event log write failed.'
  }

  # Formatted console output (host stream)
  $summaryObj = [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Timestamp = Get-Date }
  $findingsAL = [System.Collections.ArrayList]::new()
  foreach ($finding in @($script:Findings.ToArray())) {
    [void]$findingsAL.Add($finding)
  }
  Write-ConsoleSummary -Summary $summaryObj -Findings $findingsAL `
    -CustomFields ([ordered]@{
      Status = $(if ($ok) { 'COMPLIANT' } else { 'NON-COMPLIANT' })
      Proof  = $outFile
    })
  # TPM status
  $tpm = $proof.Results.TPM
  if ($tpm) {
    $tpmPresent = [bool]$tpm.Present
    $tpmKind = if ($tpmPresent) { 'OK' } else { 'ERR' }
    Write-UiLine -Text ("TPM    : {0}" -f $(if ($tpmPresent) { "Present" } else { "Missing/No Access" })) -Color $tpmKind
    if ($tpmPresent) {
      Write-UiLine -Text ("         SpecVersion={0}, Owned={1}, Enabled={2}, Activated={3}, Ready={4}" -f $tpm.SpecVersion,$tpm.IsOwned,$tpm.Enabled,$tpm.Activated,$tpm.Ready) -Color 'DIM'
    }
  }
  # SecureBoot status
  Write-UiLine -Text ("Secure : {0}" -f $(if ($proof.Results.SecureBoot) { "Secure Boot ON" } else { "Secure Boot OFF/Unknown" })) -Color $(if ($proof.Results.SecureBoot) { 'OK' } else { 'WARN' })
  # BitLocker status
  $blOk = $proof.Results.BitLockerOsProtected
  Write-UiLine -Text ("BL(OS) : {0}" -f $(if ($blOk) { "Protection ON" } else { "Protection OFF/Unknown" })) -Color $(if ($blOk) { 'OK' } else { 'WARN' })
  # Drifts
  Write-UiLine ""
  if ($drifts.Count -gt 0) {
    Write-UiLine -Text "Drifts :" -Color 'ERR'
    foreach ($d in $drifts) { Write-UiLine -Text ("- {0}" -f $d) -Color 'ERR' }
  } else {
    Write-UiLine -Text "Drifts : (none)" -Color 'OK'
  }
  # Notes
  if ($notes.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine -Text "Notes  :" -Color 'WARN'
    foreach ($n in $notes) { Write-UiLine -Text ("- {0}" -f $n) -Color 'WARN' }
  } else {
    Write-UiLine -Text "Notes  : (none)" -Color 'DIM'
  }

  # Pipeline output: one structured object only
  [pscustomobject]$proof
}
catch {
  $errMsg = "Hardware/TPM-Audit failed: " + $_.Exception.Message
  Add-ListItem -List ([ref]$errors) -Text $errMsg
  Write-HealthEvent -Id 4900 -Message $errMsg -Level 'Error' -Source $EventSource -LogName $EventLogName
  Write-UiHeader -Title "Hardware/TPM Audit Summary"
  Write-UiLine -Text $errMsg -Color 'ERR'
}

foreach ($d in @($drifts)) {
  # Map drift strings to finding codes based on content keywords
  $code = 'HW-Drift'
  if ($d -match 'TPM')       { $code = 'HW-TPMDrift' }
  if ($d -match 'Secure')    { $code = 'HW-SecureBootDrift' }
  if ($d -match 'BitLocker') { $code = 'HW-BitLockerDrift' }
  [void](Add-Finding -FindingList $script:Findings -Code $code -Severity 'High' -Message $d)
}
foreach ($e in @($errors)) {
  [void](Add-Finding -FindingList $script:Findings -Code 'HW-Error' -Severity 'High' -Message $e)
}
if ($eventWriteSucceeded -eq $false) {
  [void](Add-Finding -FindingList $script:Findings -Code 'HW-EventLogWriteFailed' -Severity 'Medium' -Message 'Required event log write failed.')
}

# V2 output contract
$resultToken = if ($errors.Count -gt 0 -or $fatalComplianceFailure) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$summary = [pscustomobject]@{
  ComputerName         = $env:COMPUTERNAME
  Timestamp            = Get-Date
  Drifts               = $drifts.ToArray()
  Errors               = $errors.ToArray()
  FatalComplianceFailure = $fatalComplianceFailure
  EventSourceSucceeded = $eventSourceOk
  EventWriteSucceeded  = $eventWriteSucceeded
}
$v2Result = Get-V2ResultObject -ScriptName '15-HardwareTPM-Audit.ps1' -Mode $Mode -Result $resultToken -Findings $script:Findings.ToArray() -Summary $summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
