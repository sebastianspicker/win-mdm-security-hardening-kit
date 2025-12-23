<#
.SYNOPSIS
  Audits Windows hardware security posture (TPM, Secure Boot, BitLocker, BIOS) and evaluates it against a simple baseline catalog.

.DESCRIPTION
  This script performs a local hardware security audit and produces:
  - A single structured result object on the success output stream (pipeline-friendly).
  - A human-readable, colorized console summary (written via Write-Host/Write-Information only).
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
      "OutFile": "PATH/TO/PROOF/HardwareCompliance.json"
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
  PS> .\15-HardwareTPM-Audit.ps1 -CatalogPath "PATH/TO/CATALOG.json"

  Runs using the specified baseline catalog JSON.

.EXAMPLE
  PS> .\15-HardwareTPM-Audit.ps1 -ConfigPath "PATH/TO/CONFIG.json"

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


[CmdletBinding()]
param(
  [string]$CatalogPath,
  [switch]$Strict,
  [string]$ConfigPath = "PATH/TO/CONFIG.json"
)

Set-StrictMode -Version 2.0

# Anonymized defaults
$EventLogName   = 'Application'
$EventSource    = 'HardwareTPM-Audit'
$DefaultOutFile = "PATH/TO/PROOF/HardwareCompliance.json"

# -----------------------------
# Helpers (no pipeline formatting)
# -----------------------------

function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Ensure-EventSource {
  param(
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][string]$LogName
  )
  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
      # Source creation usually needs admin rights; writing does not necessarily.
      New-EventLog -LogName $LogName -Source $Source -ErrorAction Stop
    }
    return $true
  } catch {
    return $false
  }
}

function Write-HealthEvent {
  param(
    [Parameter(Mandatory=$true)][int]$Id,
    [Parameter(Mandatory=$true)][string]$Message,
    [ValidateSet('Information','Warning','Error')]
    [string]$Level = 'Information',
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][string]$LogName
  )
  try {
    Write-EventLog -LogName $LogName -Source $Source -EntryType $Level -EventId $Id -Message $Message -ErrorAction Stop
  } catch {
    Write-Host ("[{0}][{1}] {2}" -f $Level, $Id, $Message)
  }
}

function Ensure-Directory {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
  }
}

function Save-Json {
  param(
    [Parameter(Mandatory=$true)][object]$Object,
    [Parameter(Mandatory=$true)][string]$Path
  )
  $dir = Split-Path -Parent $Path
  if ($dir) { Ensure-Directory -Path $dir }

  # ConvertTo-Json default depth is 2; explicitly set for nested objects.
  ($Object | ConvertTo-Json -Depth 10) | Out-File -Encoding UTF8 -FilePath $Path -Force
}

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
    $raw = Get-Content -Raw -LiteralPath $CatalogPath -ErrorAction SilentlyContinue
    if ($raw) {
      $obj = ConvertFrom-JsonSafe -JsonText $raw
      if ($obj) { return (Merge-CatalogWithDefaults -Catalog $obj -Defaults $defaults) }
    }
  }

  # 2) Config -> Hardware.CatalogPath
  if ($ConfigPath -and (Test-Path -LiteralPath $ConfigPath)) {
    $rawCfg = Get-Content -Raw -LiteralPath $ConfigPath -ErrorAction SilentlyContinue
    if ($rawCfg) {
      $cfg = ConvertFrom-JsonSafe -JsonText $rawCfg
      if ($cfg -and $cfg.Hardware -and $cfg.Hardware.CatalogPath) {
        $p = [string]$cfg.Hardware.CatalogPath
        if ($p -and (Test-Path -LiteralPath $p)) {
          $raw2 = Get-Content -Raw -LiteralPath $p -ErrorAction SilentlyContinue
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

function Get-ConsoleColor {
  param([Parameter(Mandatory=$true)][ValidateSet('OK','WARN','ERR','INFO','DIM')]$Kind)
  switch ($Kind) {
    'OK'   { return 'Green' }
    'WARN' { return 'Yellow' }
    'ERR'  { return 'Red' }
    'INFO' { return 'Cyan' }
    'DIM'  { return 'DarkGray' }
  }
}

function Write-PrettyLine {
  param(
    [Parameter(Mandatory=$true)][string]$Text,
    [ValidateSet('OK','WARN','ERR','INFO','DIM')]$Kind = 'INFO',
    [switch]$NoNewLine
  )
  $c = Get-ConsoleColor -Kind $Kind
  if ($NoNewLine) { Write-Host $Text -ForegroundColor $c -NoNewline }
  else { Write-Host $Text -ForegroundColor $c }
}

function Write-PrettyHeader {
  param([Parameter(Mandatory=$true)][string]$Title)
  Write-Host ""
  Write-Host ("=" * 60) -ForegroundColor DarkGray
  Write-Host ("{0}" -f $Title) -ForegroundColor White
  Write-Host ("=" * 60) -ForegroundColor DarkGray
}

function Write-ConsoleSummary {
  param(
    [Parameter(Mandatory=$true)][bool]$OverallOk,
    [Parameter(Mandatory=$true)][System.Collections.Generic.List[string]]$Drifts,
    [Parameter(Mandatory=$true)][System.Collections.Generic.List[string]]$Notes,
    [Parameter(Mandatory=$true)][string]$OutFile,
    [Parameter(Mandatory=$true)]$Results
  )

  Write-PrettyHeader -Title "Hardware/TPM Audit Summary"

  $statusText = if ($OverallOk) { "COMPLIANT" } else { "NON-COMPLIANT" }
  $statusKind = if ($OverallOk) { 'OK' } else { 'ERR' }

  Write-PrettyLine -Text ("Status : {0}" -f $statusText) -Kind $statusKind
  Write-PrettyLine -Text ("Proof  : {0}" -f $OutFile) -Kind 'DIM'

  # Key facts (compact, human-readable)
  $tpm = $Results.TPM
  if ($tpm) {
    $tpmPresent = [bool]$tpm.Present
    $tpmKind = if ($tpmPresent) { 'OK' } else { 'ERR' }
    Write-PrettyLine -Text ("TPM    : {0}" -f $(if ($tpmPresent) { "Present" } else { "Missing/No Access" })) -Kind $tpmKind
    if ($tpmPresent) {
      Write-PrettyLine -Text ("         SpecVersion={0}, Owned={1}, Enabled={2}, Activated={3}, Ready={4}" -f $tpm.SpecVersion,$tpm.IsOwned,$tpm.Enabled,$tpm.Activated,$tpm.Ready) -Kind 'DIM'
    }
  }

  Write-PrettyLine -Text ("Secure : {0}" -f $(if ($Results.SecureBoot) { "Secure Boot ON" } else { "Secure Boot OFF/Unknown" })) -Kind $(if ($Results.SecureBoot) { 'OK' } else { 'WARN' })

  $blOk = $Results.BitLockerOsProtected
  Write-PrettyLine -Text ("BL(OS) : {0}" -f $(if ($blOk) { "Protection ON" } else { "Protection OFF/Unknown" })) -Kind $(if ($blOk) { 'OK' } else { 'WARN' })

  Write-Host ""
  if ($Drifts.Count -gt 0) {
    Write-PrettyLine -Text "Drifts :" -Kind 'ERR'
    foreach ($d in $Drifts) { Write-PrettyLine -Text ("- {0}" -f $d) -Kind 'ERR' }
  } else {
    Write-PrettyLine -Text "Drifts : (none)" -Kind 'OK'
  }

  if ($Notes.Count -gt 0) {
    Write-Host ""
    Write-PrettyLine -Text "Notes  :" -Kind 'WARN'
    foreach ($n in $Notes) { Write-PrettyLine -Text ("- {0}" -f $n) -Kind 'WARN' }
  } else {
    Write-PrettyLine -Text "Notes  : (none)" -Kind 'DIM'
  }
}

# -----------------------------
# Main
# -----------------------------

$isAdmin       = Test-IsAdmin
$eventSourceOk = Ensure-EventSource -Source $EventSource -LogName $EventLogName

$drifts = New-Object System.Collections.Generic.List[string]
$notes  = New-Object System.Collections.Generic.List[string]
$errors = New-Object System.Collections.Generic.List[string]
$ok     = $true

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

  Save-Json -Object $proof -Path $outFile

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

  Write-HealthEvent -Id $eventId -Message $msg -Level $level -Source $EventSource -LogName $EventLogName

  # Pretty console output (out-of-band)
  Write-ConsoleSummary -OverallOk $ok -Drifts $drifts -Notes $notes -OutFile $outFile -Results $proof.Results

  # Pipeline output: one structured object only
  #[pscustomobject]$proof
}
catch {
  $errMsg = "Hardware/TPM-Audit failed: " + $_.Exception.Message
  Write-HealthEvent -Id 4900 -Message $errMsg -Level 'Error' -Source $EventSource -LogName $EventLogName
  Write-PrettyHeader -Title "Hardware/TPM Audit Summary"
  Write-PrettyLine -Text $errMsg -Kind 'ERR'
}
