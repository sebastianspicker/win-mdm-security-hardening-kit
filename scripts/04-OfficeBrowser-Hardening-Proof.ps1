#requires -version 5.1
<#
.SYNOPSIS
  Evaluates and (optionally) enforces a hardened baseline for Microsoft Office, Microsoft Edge, and Mozilla Firefox, with drift detection and proof generation.

.DESCRIPTION
  This script validates a set of security-relevant configuration items for Office, Edge, and Firefox against an expected baseline ("catalog").
  It can run in two modes:
  - Audit mode (default): Detects drift and reports compliance without changing the system.
  - Remediation mode (-Mode Remediate): Applies the baseline settings (idempotent) and then re-checks compliance.

  The script produces two kinds of output:
  - Human-readable console output (status blocks, warnings, and a final summary).
  - Machine-readable pipeline output: a list of structured objects (one object per check) suitable for Export-Csv, ConvertTo-Json, filtering, etc.

  A proof JSON file is written at the end, containing:
  - Execution metadata (time, host, mode flags).
  - A summary (total checks, non-compliant checks, changed items).
  - The full per-check result list (expected/actual/compliant/changed/message).

  Catalog loading behavior:
  - If -CatalogPath is provided, it is used as the catalog source.
  - Otherwise, the script tries to read -ConfigPath and uses OfficeBrowser.CatalogPath if present.
  - If no catalog can be loaded or parsing fails, embedded defaults are used.
  - Missing sections (Office/Edge/Firefox/Proof) are automatically filled with embedded defaults.

  Permissions / scope:
  - Office settings are written under HKCU (current user).
  - Edge settings are written under HKLM (system-wide).
  - Firefox policies are written to a policies.json under the Firefox distribution directory (usually under Program Files).
  When not running elevated, write operations for system-wide locations may fail; audit mode still works.

.PARAMETER CatalogPath
  Path to the catalog JSON file that defines the desired baseline (Office/Edge/Firefox settings and optional proof output path).
  If the file is missing or invalid, embedded defaults are used.

.PARAMETER ConfigPath
  Path to an optional configuration JSON.
  If present, the script looks for:
    { "OfficeBrowser": { "CatalogPath": "[configured path]" } }
  If the config file is missing or invalid, it is ignored and embedded defaults are used.

.PARAMETER Strict
  Switch. Enables strict compliance evaluation.


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

  One output object per check is written to the pipeline at the end of the script.
  Each object contains these core fields:
  - Time: Timestamp (ISO-like string).
  - Product: 'Office', 'Edge', or 'Firefox'.
  - Area: Sub-area / component (for grouping).
  - Policy: Logical policy name.
  - Target: Registry path or file path.
  - Name: Registry value name or file name.
  - Type: 'DWord', 'String', or 'File'.
  - Expected: Expected value (or expected file state).
  - Actual: Detected value (or detected file state).
  - Compliant: True if actual matches expected after evaluation (and remediation if enabled).
  - Changed: True if the script changed something during this run.
  - Message: Optional human-readable status (e.g. drift detected, write failed, set applied).

.NOTES
  Proof file location:
  - Default: $env:TEMP\OfficeBrowser-Hardening-Proof.json
  - Can be overridden via the catalog field: Proof.OutFile

  Exit codes:
  - 0 = OK, 2 = WARN, 1 = FAIL.

  Recommended usage:
  - Use audit mode for continuous compliance checks (e.g., scheduled task).
  - Use remediation mode for controlled baseline enforcement (e.g., during provisioning).
  - Consume the pipeline objects for reporting (CSV/JSON) and automation.

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1

  Runs in audit mode using the embedded defaults (or a catalog resolved via ConfigPath if available).
  Writes a proof JSON file and outputs per-check objects to the pipeline.

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1 -CatalogPath $CatalogPath

  Runs audit mode using the specified catalog JSON as the baseline source.

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1 -Mode Remediate

  Runs remediation mode: applies the baseline settings and re-checks compliance.
  Returns a V2 result and its corresponding process exit code.

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1 -Mode Remediate -Strict; exit $LASTEXITCODE

  Runs remediation mode with strict compliance evaluation.
  Useful for CI-style compliance enforcement.

.EXAMPLE
  $results = .\04-OfficeBrowser-Hardening-Proof.ps1
  $results | Where-Object { -not $_.Compliant } | Format-Table -AutoSize

  Runs the script and filters the pipeline output for non-compliant items.

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1 | Export-Csv -NoTypeInformation -Path $OutputPath

  Runs the script and exports the per-check results to CSV for reporting.
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
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '04-OfficeBrowser-Hardening-Proof.ps1' -BoundParameters $PSBoundParameters `
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
  $result = Get-V2ResultObject -ScriptName '04-OfficeBrowser-Hardening-Proof.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

if (-not $Quiet) { $InformationPreference = 'Continue' }   # Information stream shown by default

$script:Findings = Get-FindingsList

$EventSource      = 'OfficeBrowser-Hardening'
$EventLog         = 'Application'
$DefaultProofPath = Join-Path ([System.IO.Path]::GetTempPath()) 'OfficeBrowser-Hardening-Proof.json'

$DefaultCatalogJson = @"
{
  "Office": {
    "VersionMajor": 16,
    "MacrosMode": "SignedOnly",
    "BlockMacrosFromInternet": true,
    "DisableTrustedLocations": true,
    "ProtectedView": { "Internet": true, "UnsafeLocations": true, "Outlook": true },
    "AccessVBOM": false
  },
  "Edge": {
    "PolicyHive": "Mandatory",
    "SmartScreen": true,
    "PUA": true,
    "TrackingPrevention": "Balanced",
    "PasswordManager": false,
    "AutofillAddress": false,
    "AutofillCreditCard": false,
    "SSLVersionMin": "tls1.2",
    "SyncDisabled": true,
    "HomePageURL": null,
    "RestoreOnStartup": 4,
    "StartupURLs": []
  },
  "Firefox": {
    "Enable": true,
    "DistributionDir": null,
    "DisableAppUpdate": true,
    "DisableTelemetry": true,
    "PasswordManagerEnabled": false,
    "TrackingProtection": "strict",
    "TLSMin": 3,
    "BlockAllAddonsExcept": [],
    "InstallAddons": []
  },
  "Proof": {
    "OutFile": null
  }
}
"@

# -----------------------------
# Utilities
# -----------------------------

# Test-IsAdmin imported from lib/Common.psm1


# Ensure-Key replaced by Ensure-RegistryKey from lib/Registry.psm1

. (Join-Path $PSScriptRoot 'internal/04-OfficeBrowser-Hardening-Proof.helpers.ps1')

function Set-RegValueProof {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][string]$Product,
    [Parameter(Mandatory)][string]$Area,
    [Parameter(Mandatory)][string]$Policy,
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('DWord','String')][string]$Type,
    [Parameter(Mandatory)]$Value,
    [switch]$Remediate
  )

  # Only ensure key exists when remediating (§2/§17)
  $expected = Convert-RegValue -Type $Type -Value $Value
  $cur      = Get-RegValue -Path $Path -Name $Name

  $compliant = ($cur -eq $expected)
  $changed   = $false
  $msg       = $null

  if (-not $compliant) {
    if ($Remediate) {
      if (-not $PSCmdlet.ShouldProcess("$Path\$Name", "Set $Type value")) {
        return (Get-ProofItem -Product $Product -Area $Area -Policy $Policy -Target $Path -Name $Name -Type $Type -Expected $expected -Actual $cur -Compliant $false -Changed $false -Message 'Set skipped by confirmation/WhatIf')
      }

      try {
        Ensure-RegistryKey -Path $Path
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $expected -Force -ErrorAction Stop | Out-Null
        $changed = $true
      } catch {
        $msg = "Write failed: $($_.Exception.Message)"
      }

      $cur = Get-RegValue -Path $Path -Name $Name
      $compliant = ($cur -eq $expected)

      if (-not $msg) {
        $msg = $(if ($compliant) { 'Set applied' } else { 'Set attempted but differs' })
      }
    } else {
      $compliant = $false
      $msg = 'Drift detected'
    }
  }

  Get-ProofItem -Product $Product -Area $Area -Policy $Policy -Target $Path -Name $Name -Type $Type -Expected $expected -Actual $cur -Compliant $compliant -Changed $changed -Message $msg
}


function Ensure-Edge {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][object]$EdgeCfg,
    [switch]$Remediate
  )

  $items = New-Object System.Collections.Generic.List[object]
  $base  = Get-EdgeBaseKey -EdgeCfg $EdgeCfg

  foreach ($policy in Get-EdgePolicyDefinitions -EdgeCfg $EdgeCfg) {
    $items.Add((Set-RegValueProof -Product 'Edge' -Area $policy.Area -Policy $policy.Policy -Path $base -Name $policy.Name -Type $policy.Type -Value $policy.Value -Remediate:$Remediate)) | Out-Null
  }

  $hp = Get-TextOrNull $EdgeCfg.HomePageURL
  if ($hp) {
    $r = Set-RegValueProof -Product 'Edge' -Area 'UX' -Policy 'HomepageLocation' -Path $base -Name 'HomepageLocation' -Type String -Value $hp -Remediate:$Remediate
    $items.Add($r) | Out-Null

    $r = Set-RegValueProof -Product 'Edge' -Area 'UX' -Policy 'HomepageIsNewTabPage' -Path $base -Name 'HomepageIsNewTabPage' -Type DWord -Value 0 -Remediate:$Remediate
    $items.Add($r) | Out-Null
  }

  if ($null -ne $EdgeCfg.RestoreOnStartup) {
    $r = Set-RegValueProof -Product 'Edge' -Area 'Startup' -Policy 'RestoreOnStartup' -Path $base -Name 'RestoreOnStartup' -Type DWord -Value ([int]$EdgeCfg.RestoreOnStartup) -Remediate:$Remediate
    $items.Add($r) | Out-Null
  }

  $urlsKey = Join-Path $base 'RestoreOnStartupURLs'
  $desiredUrls = Get-EdgeStartupUrlMap -StartupURLs $EdgeCfg.StartupURLs

  if ($Remediate) {
    if ($PSCmdlet.ShouldProcess($urlsKey, 'Reset Edge startup URLs')) {
      Ensure-RegistryKey -Path $urlsKey
      Clear-EdgeStartupUrlValues -Path $urlsKey
    }

    foreach ($name in @($desiredUrls.Keys | Sort-Object { [int]$_ })) {
      $expected = $desiredUrls[$name]
      if ($PSCmdlet.ShouldProcess("$urlsKey\$name", 'Set Edge startup URL')) {
        $items.Add((Set-EdgeStartupUrlProof -Path $urlsKey -Name $name -Expected $expected)) | Out-Null
      } else {
        $items.Add((Set-EdgeStartupUrlProof -Path $urlsKey -Name $name -Expected $expected -Skipped)) | Out-Null
      }
    }
  } else {
    $currentUrls = Get-EdgeStartupUrlValues -Path $urlsKey
    foreach ($item in Get-EdgeStartupUrlAuditProofItems -Path $urlsKey -DesiredUrls $desiredUrls -CurrentUrls $currentUrls) { $items.Add($item) | Out-Null }
  }

  return $items
}


# -----------------------------
# Main
# -----------------------------

if (-not (Ensure-EventSource -Source $EventSource -Log $EventLog)) {
  Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
}

$isAdmin     = Test-IsAdmin
$globalNotes = New-Object System.Collections.Generic.List[string]
$proofPath   = $DefaultProofPath
$overallOk   = $true

$catalogInfo = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath -DefaultCatalogJson $DefaultCatalogJson
foreach($n in $catalogInfo.Notes) { $globalNotes.Add($n) | Out-Null }

if (-not $isAdmin) {
  $globalNotes.Add("Not elevated: HKLM (Edge) and Program Files (Firefox) writes may fail.") | Out-Null
}

$cat = $catalogInfo.Catalog
$proofOverride = Get-TextOrNull $cat.Proof.OutFile
if ($proofOverride) { $proofPath = $proofOverride }

$allItems = New-Object System.Collections.Generic.List[object]

try {
  foreach($i in (Ensure-Office  -OfficeCfg  $cat.Office  -Remediate:$Remediate)) { $allItems.Add($i) | Out-Null }
  foreach($i in (Ensure-Edge    -EdgeCfg    $cat.Edge    -Remediate:$Remediate)) { $allItems.Add($i) | Out-Null }
  foreach($i in (Ensure-Firefox -FirefoxCfg $cat.Firefox -Remediate:$Remediate)) { $allItems.Add($i) | Out-Null }
} catch {
  $overallOk = $false
  $globalNotes.Add("Unhandled error during evaluation: $($_.Exception.Message)") | Out-Null
}

$allSafe = @($allItems | ForEach-Object { Ensure-ProofItemLike $_ })

$nonCompliant = @($allSafe | Where-Object { (Bool-Prop $_ 'Compliant' $true) -eq $false })
if ($nonCompliant.Count -gt 0) { $overallOk = $false }

$changedCount = @($allSafe | Where-Object { (Bool-Prop $_ 'Changed' $false) -eq $true }).Count

$proof = [ordered]@{
  Time      = (Get-Date).ToString("s")
  Hostname  = $env:COMPUTERNAME
  Strict    = [bool]$Strict
  Remediate = [bool]$Remediate
  IsAdmin   = [bool]$isAdmin
  Catalog   = [ordered]@{ LoadedFrom = $catalogInfo.LoadedFrom }
  Notes     = @($globalNotes)
  Summary   = [ordered]@{
    TotalItems   = $allSafe.Count
    NonCompliant = $nonCompliant.Count
    Changed      = $changedCount
  }
  Items     = @($allSafe)
}

try {
  Save-Json -InputObject $proof -Path $proofPath -NoBom
} catch {
  $overallOk = $false
  $globalNotes.Add("Failed to write proof JSON: $($_.Exception.Message)") | Out-Null
}

try {
  $eventId = 4940
  $level   = 'Information'
  if (-not $overallOk -or $Strict) { $eventId = 4950; $level = 'Warning' }

  $msg = @(
    ("Office/Browser hardening: Ok={0} Strict={1} Remediate={2}" -f $overallOk, [bool]$Strict, [bool]$Remediate),
    ("TotalItems={0} NonCompliant={1} Changed={2}" -f $proof.Summary.TotalItems, $proof.Summary.NonCompliant, $proof.Summary.Changed),
    ("Proof JSON: {0}" -f $proofPath)
  ) -join "`r`n"

  Write-HealthEvent -Id $eventId -Msg $msg -Level $level -Source $EventSource -Log $EventLog
} catch {
  Write-Verbose ("Office/browser health event write failed: {0}" -f $_.Exception.Message)
}

Write-ConsoleSummary -AllItems @($allSafe) -CatalogInfo $catalogInfo -ProofPath $proofPath -IsAdmin $isAdmin -Remediate ([bool]$Remediate) -Strict ([bool]$Strict) -Notes @($globalNotes)

foreach ($nc in @($nonCompliant)) {
  $prod = if ($nc.PSObject.Properties['Product']) { $nc.Product } else { 'Unknown' }
  $area = if ($nc.PSObject.Properties['Area']) { $nc.Area } else { '' }
  $name = if ($nc.PSObject.Properties['Name']) { $nc.Name } else { '' }
  $msg  = if ($nc.PSObject.Properties['Message']) { $nc.Message } else { ("{0}/{1}/{2} not compliant" -f $prod, $area, $name) }
  $code = "OB-{0}" -f ($prod -replace '\s','')
  Add-Finding -FindingList $script:Findings -Code $code -Severity 'Medium' -Message $msg `
    -Extra @{ Product = $prod; Area = $area; Name = $name }
}

# V2 output contract
$resultToken = if (-not $overallOk) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '04-OfficeBrowser-Hardening-Proof.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary ([pscustomobject]@{ ComputerName = $env:COMPUTERNAME; OverallOk = $overallOk; Timestamp = Get-Date }) -Metadata @{ Notes = @($globalNotes) }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }

exit (Get-V2ExitCode -Result $resultToken)
