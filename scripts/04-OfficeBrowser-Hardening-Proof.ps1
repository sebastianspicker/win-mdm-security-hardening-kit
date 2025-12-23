<#
.SYNOPSIS
  Evaluates and (optionally) enforces a hardened baseline for Microsoft Office, Microsoft Edge, and Mozilla Firefox, with drift detection and proof generation.

.DESCRIPTION
  This script validates a set of security-relevant configuration items for Office, Edge, and Firefox against an expected baseline ("catalog").
  It can run in two modes:
  - Audit mode (default): Detects drift and reports compliance without changing the system.
  - Remediation mode (-Remediate): Applies the baseline settings (idempotent) and then re-checks compliance.

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
    { "OfficeBrowser": { "CatalogPath": "PATH/TO/CATALOG.json" } }
  If the config file is missing or invalid, it is ignored and embedded defaults are used.

.PARAMETER Remediate
  Switch. When specified, the script attempts to enforce the desired baseline settings.
  Without this switch, the script only detects drift (no changes are made).

.PARAMETER Strict
  Switch. When specified, the script returns exit code 1 whenever drift is detected,
  even if remediation was enabled and some items were successfully changed.

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
  - Default: PATH/TO/PROOF.json
  - Can be overridden via the catalog field: Proof.OutFile

  Exit codes:
  - 0: No drift detected (all checks compliant) and Strict is not set.
  - 1: Drift detected, or Strict is set (Strict forces a non-zero exit code regardless of remediation outcome).

  Recommended usage:
  - Use audit mode for continuous compliance checks (e.g., scheduled task).
  - Use remediation mode for controlled baseline enforcement (e.g., during provisioning).
  - Consume the pipeline objects for reporting (CSV/JSON) and automation.

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1

  Runs in audit mode using the embedded defaults (or a catalog resolved via ConfigPath if available).
  Writes a proof JSON file and outputs per-check objects to the pipeline.

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1 -CatalogPath "PATH/TO/CATALOG.json"

  Runs audit mode using the specified catalog JSON as the baseline source.

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1 -Remediate

  Runs remediation mode: applies the baseline settings and re-checks compliance.
  Returns exit code 1 only if drift remains (unless -Strict is also used).

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1 -Remediate -Strict; exit $LASTEXITCODE

  Runs remediation mode, but forces exit code 1 if any drift was detected at any point.
  Useful for CI-style compliance enforcement.

.EXAMPLE
  $results = .\04-OfficeBrowser-Hardening-Proof.ps1
  $results | Where-Object { -not $_.Compliant } | Format-Table -AutoSize

  Runs the script and filters the pipeline output for non-compliant items.

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1 | Export-Csv -NoTypeInformation -Path "PATH/TO/report.csv"

  Runs the script and exports the per-check results to CSV for reporting.
#>


[CmdletBinding()]
param(
  [string]$CatalogPath,
  [switch]$Remediate,
  [switch]$Strict,
  [string]$ConfigPath = "PATH/TO/CONFIG.json"
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'   # Information stream shown by default

$EventSource      = 'OfficeBrowser-Hardening'
$EventLog         = 'Application'
$DefaultProofPath = "PATH/TO/PROOF.json"

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
    "OutFile": "PATH/TO/PROOF.json"
  }
}
"@

# -----------------------------
# Utilities
# -----------------------------

function Ensure-EventSource {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Log
  )
  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {  # may require admin rights
      New-EventLog -LogName $Log -Source $Source -ErrorAction Stop
    }
  } catch {
    # Event source creation requires elevation; ignore on failure.
  }
}

function Write-HealthEvent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][int]$Id,
    [Parameter(Mandatory)][string]$Msg,
    [ValidateSet('Information','Warning','Error')][string]$Level = 'Information',
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Log
  )
  try {
    Write-EventLog -LogName $Log -Source $Source -EntryType $Level -EventId $Id -Message $Msg
  } catch {
    Write-Host "[$Level][$Id] $Msg" -ForegroundColor Yellow
  }
}

function Is-Admin {
  [CmdletBinding()]
  param()
  try {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

function Ensure-Dir {
  [CmdletBinding()]
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
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

function Get-TextOrNull {
  [CmdletBinding()]
  param($Value)
  if ($null -eq $Value) { return $null }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  return $s
}

function Get-BoolDefault {
  [CmdletBinding()]
  param(
    $Value,
    [bool]$Default
  )
  if ($null -eq $Value) { return $Default }
  try { return [bool]$Value } catch { return $Default }
}

function Get-IntDefault {
  [CmdletBinding()]
  param(
    $Value,
    [int]$Default
  )
  if ($null -eq $Value) { return $Default }
  try { return [int]$Value } catch { return $Default }
}

function Get-ArrayStrings {
  [CmdletBinding()]
  param($Value)
  if ($null -eq $Value) { return @() }
  if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
    $out = @()
    foreach($x in $Value) {
      $s = Get-TextOrNull $x
      if ($s) { $out += $s }
    }
    return $out
  }
  $s2 = Get-TextOrNull $Value
  if (-not $s2) { return @() }
  return @($s2)
}

function Save-Json {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$Obj,
    [Parameter(Mandatory)][string]$Path
  )

  $dir = Split-Path -Parent $Path
  Ensure-Dir -Path $dir

  $json = $Obj | ConvertTo-Json -Depth 20
  $utf8NoBOM = New-Object System.Text.UTF8Encoding($false)  # UTF-8 without BOM
  [System.IO.File]::WriteAllText($Path, $json, $utf8NoBOM)
}

function Get-RegValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name
  )
  try {
    $p = Get-ItemProperty -Path $Path -ErrorAction Stop
    if ($null -ne $p.PSObject.Properties[$Name]) { return $p.$Name }
    return $null
  } catch {
    return $null
  }
}

function Convert-RegValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('DWord','String')][string]$Type,
    [Parameter(Mandatory)]$Value
  )
  switch ($Type) {
    'DWord'  { return [int]$Value }
    'String' { return [string]$Value }
  }
}

function New-ProofItem {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Product,
    [Parameter(Mandatory)][string]$Area,
    [Parameter(Mandatory)][string]$Policy,
    [Parameter(Mandatory)][string]$Target,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('DWord','String','File')][string]$Type,
    [Parameter(Mandatory)]$Expected,
    $Actual,
    [bool]$Compliant,
    [bool]$Changed,
    [string]$Message
  )
  [pscustomobject]@{
    Time      = (Get-Date).ToString("s")
    Product   = $Product
    Area      = $Area
    Policy    = $Policy
    Target    = $Target
    Name      = $Name
    Type      = $Type
    Expected  = $Expected
    Actual    = $Actual
    Compliant = [bool]$Compliant
    Changed   = [bool]$Changed
    Message   = $Message
  }
}

function Set-RegValueProof {
  [CmdletBinding()]
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

  Ensure-Key -Path $Path

  $expected = Convert-RegValue -Type $Type -Value $Value
  $cur      = Get-RegValue -Path $Path -Name $Name

  $compliant = ($cur -eq $expected)
  $changed   = $false
  $msg       = $null

  if (-not $compliant) {
    if ($Remediate) {
      try {
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

  New-ProofItem -Product $Product -Area $Area -Policy $Policy -Target $Path -Name $Name -Type $Type -Expected $expected -Actual $cur -Compliant $compliant -Changed $changed -Message $msg
}

function Get-EdgeBaseKey {
  [CmdletBinding()]
  param([object]$EdgeCfg)
  $mode = Get-TextOrNull $EdgeCfg.PolicyHive
  if ($mode -and ($mode -ieq 'Recommended')) {
    return 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\Recommended'
  }
  return 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
}

function Has-Prop {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Obj,
    [Parameter(Mandatory)][string]$Name
  )
  if ($null -eq $Obj) { return $false }
  try { return ($Obj.PSObject.Properties.Match($Name).Count -gt 0) } catch { return $false }
}

function Bool-Prop {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Obj,
    [Parameter(Mandatory)][string]$Name,
    [bool]$Default = $false
  )
  if (-not (Has-Prop $Obj $Name)) { return $Default }
  try { return [bool]$Obj.$Name } catch { return $Default }
}

function Ensure-ProofItemLike {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Obj)

  if ($null -eq $Obj) {
    return (New-ProofItem -Product 'System' -Area 'Pipeline' -Policy 'NullItem' -Target 'N/A' -Name 'Null' -Type String -Expected 'ProofItem' -Actual $null -Compliant $false -Changed $false -Message 'Unexpected null item')
  }
  if ((Has-Prop $Obj 'Product') -and (Has-Prop $Obj 'Compliant') -and (Has-Prop $Obj 'Changed')) {
    return $Obj
  }
  return (New-ProofItem -Product 'System' -Area 'Pipeline' -Policy 'NonProofObject' -Target 'N/A' -Name ($Obj.GetType().FullName) -Type String -Expected 'ProofItem' -Actual ($Obj | Out-String) -Compliant $false -Changed $false -Message 'Non-proof object leaked into pipeline')
}

function New-ResultSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Section,
    [Parameter(Mandatory)][object[]]$Items
  )

  $all = @($Items | ForEach-Object { Ensure-ProofItemLike $_ })
  $non = @($all | Where-Object { (Bool-Prop $_ 'Compliant' $true) -eq $false })
  $chg = @($all | Where-Object { (Bool-Prop $_ 'Changed' $false) -eq $true })

  [pscustomobject]@{
    Section      = $Section
    Ok           = ($non.Count -eq 0)
    Total        = $all.Count
    NonCompliant = $non.Count
    Changed      = $chg.Count
  }
}

function Load-Catalog {
  [CmdletBinding()]
  param(
    [string]$CatalogPath,
    [string]$ConfigPath,
    [string]$DefaultCatalogJson
  )

  $notes      = New-Object System.Collections.Generic.List[string]
  $cat        = $null
  $loadedFrom = $null

  $default = $null
  try {
    $default = $DefaultCatalogJson | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "Embedded default catalog JSON is invalid: $($_.Exception.Message)"
  }

  $p = Get-TextOrNull $CatalogPath
  if ($p) {
    if (Test-Path -LiteralPath $p) {
      try {
        $cat = Get-Content -Raw -Path $p | ConvertFrom-Json -ErrorAction Stop
        $loadedFrom = 'CatalogPath'
      } catch {
        $notes.Add('CatalogPath JSON parse failed; using embedded defaults.') | Out-Null
      }
    } else {
      $notes.Add('CatalogPath not found; using embedded defaults.') | Out-Null
    }
  }

  if (-not $cat) {
    $cp = Get-TextOrNull $ConfigPath
    if ($cp) {
      if (Test-Path -LiteralPath $cp) {
        try {
          $cfg = Get-Content -Raw -Path $cp | ConvertFrom-Json -ErrorAction Stop
          $cfgCat = $null

          if ($cfg -and $cfg.PSObject.Properties['OfficeBrowser']) {
            $ob = $cfg.OfficeBrowser
            if ($ob -and $ob.PSObject.Properties['CatalogPath']) {
              $cfgCat = Get-TextOrNull $ob.CatalogPath
            }
          }

          if ($cfgCat) {
            if (Test-Path -LiteralPath $cfgCat) {
              try {
                $cat = Get-Content -Raw -Path $cfgCat | ConvertFrom-Json -ErrorAction Stop
                $loadedFrom = 'ConfigPath->OfficeBrowser.CatalogPath'
              } catch {
                $notes.Add('Config-referenced catalog JSON parse failed; using embedded defaults.') | Out-Null
              }
            } else {
              $notes.Add('Config-referenced catalog not found; using embedded defaults.') | Out-Null
            }
          } else {
            $notes.Add('ConfigPath present but OfficeBrowser.CatalogPath not set; using embedded defaults.') | Out-Null
          }
        } catch {
          $notes.Add('ConfigPath JSON parse failed; using embedded defaults.') | Out-Null
        }
      } else {
        $notes.Add('ConfigPath not found; using embedded defaults.') | Out-Null
      }
    }
  }

  if (-not $cat) {
    $cat        = $default
    $loadedFrom = 'EmbeddedDefaults'
  }

  if (-not $cat.Office)  { $cat | Add-Member -MemberType NoteProperty -Name Office  -Value $default.Office  -Force; $notes.Add('Office section missing; defaults applied.')  | Out-Null }
  if (-not $cat.Edge)    { $cat | Add-Member -MemberType NoteProperty -Name Edge    -Value $default.Edge    -Force; $notes.Add('Edge section missing; defaults applied.')    | Out-Null }
  if (-not $cat.Firefox) { $cat | Add-Member -MemberType NoteProperty -Name Firefox -Value $default.Firefox -Force; $notes.Add('Firefox section missing; defaults applied.') | Out-Null }
  if (-not $cat.Proof)   { $cat | Add-Member -MemberType NoteProperty -Name Proof   -Value $default.Proof   -Force; $notes.Add('Proof section missing; defaults applied.')   | Out-Null }

  [pscustomobject]@{
    Catalog     = $cat
    Defaults    = $default
    LoadedFrom  = $loadedFrom
    Notes       = @($notes)
  }
}

# -----------------------------
# Hardeners
# -----------------------------

function Ensure-Office {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$OfficeCfg,
    [switch]$Remediate
  )

  $items = New-Object System.Collections.Generic.List[object]
  $ver   = Get-IntDefault $OfficeCfg.VersionMajor 16
  $base  = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$ver.0"

  $apps = @('word','excel','powerpoint')
  foreach($app in $apps) {
    $appSecurity = Join-Path $base "$app\security"

    $macrosMode      = Get-TextOrNull $OfficeCfg.MacrosMode
    $wantVbaWarnings = 3
    if ($macrosMode -and ($macrosMode -ieq 'DisableAll')) { $wantVbaWarnings = 4 }

    $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'VBAWarnings' -Path $appSecurity -Name 'VBAWarnings' -Type DWord -Value $wantVbaWarnings -Remediate:$Remediate
    $items.Add($r) | Out-Null

    if (Get-BoolDefault $OfficeCfg.BlockMacrosFromInternet $true) {
      $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'BlockMacrosFromInternet' -Path $appSecurity -Name 'blockcontentexecutionfrominternet' -Type DWord -Value 1 -Remediate:$Remediate
      $items.Add($r) | Out-Null
    }

    if ($null -ne $OfficeCfg.AccessVBOM) {
      $want = if ([bool]$OfficeCfg.AccessVBOM) { 1 } else { 0 }
      $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'AccessVBOM' -Path $appSecurity -Name 'AccessVBOM' -Type DWord -Value $want -Remediate:$Remediate
      $items.Add($r) | Out-Null
    }

    $pv = $OfficeCfg.ProtectedView
    if ($pv) {
      $pvKey = Join-Path $appSecurity 'protectedview'

      if ($null -ne $pv.Internet) {
        $want = if ([bool]$pv.Internet) { 0 } else { 1 }
        $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'ProtectedViewInternet' -Path $pvKey -Name 'DisableInternetFilesInPV' -Type DWord -Value $want -Remediate:$Remediate
        $items.Add($r) | Out-Null
      }

      if ($null -ne $pv.UnsafeLocations) {
        $want = if ([bool]$pv.UnsafeLocations) { 0 } else { 1 }
        $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'ProtectedViewUnsafeLocations' -Path $pvKey -Name 'DisableUnsafeLocationsInPV' -Type DWord -Value $want -Remediate:$Remediate
        $items.Add($r) | Out-Null
      }

      if ($null -ne $pv.Outlook) {
        $want = if ([bool]$pv.Outlook) { 0 } else { 1 }
        $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'ProtectedViewOutlookAttachments' -Path $pvKey -Name 'DisableAttachmentsInPV' -Type DWord -Value $want -Remediate:$Remediate
        $items.Add($r) | Out-Null
      }
    }

    if (Get-BoolDefault $OfficeCfg.DisableTrustedLocations $true) {
      $tlKey = Join-Path $appSecurity 'trusted locations'
      $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'DisableTrustedLocations' -Path $tlKey -Name 'AllLocationsDisabled' -Type DWord -Value 1 -Remediate:$Remediate
      $items.Add($r) | Out-Null
    }
  }

  return $items
}

function Ensure-Edge {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$EdgeCfg,
    [switch]$Remediate
  )

  $items = New-Object System.Collections.Generic.List[object]
  $base  = Get-EdgeBaseKey -EdgeCfg $EdgeCfg

  $r = Set-RegValueProof -Product 'Edge' -Area 'Core' -Policy 'SmartScreenEnabled' -Path $base -Name 'SmartScreenEnabled' -Type DWord -Value ([int](Get-BoolDefault $EdgeCfg.SmartScreen $true)) -Remediate:$Remediate
  $items.Add($r) | Out-Null

  $r = Set-RegValueProof -Product 'Edge' -Area 'Core' -Policy 'SmartScreenPuaEnabled' -Path $base -Name 'SmartScreenPuaEnabled' -Type DWord -Value ([int](Get-BoolDefault $EdgeCfg.PUA $true)) -Remediate:$Remediate
  $items.Add($r) | Out-Null

  $r = Set-RegValueProof -Product 'Edge' -Area 'Core' -Policy 'PasswordManagerEnabled' -Path $base -Name 'PasswordManagerEnabled' -Type DWord -Value ([int](Get-BoolDefault $EdgeCfg.PasswordManager $false)) -Remediate:$Remediate
  $items.Add($r) | Out-Null

  $r = Set-RegValueProof -Product 'Edge' -Area 'Core' -Policy 'AutofillAddressEnabled' -Path $base -Name 'AutofillAddressEnabled' -Type DWord -Value ([int](Get-BoolDefault $EdgeCfg.AutofillAddress $false)) -Remediate:$Remediate
  $items.Add($r) | Out-Null

  $r = Set-RegValueProof -Product 'Edge' -Area 'Core' -Policy 'AutofillCreditCardEnabled' -Path $base -Name 'AutofillCreditCardEnabled' -Type DWord -Value ([int](Get-BoolDefault $EdgeCfg.AutofillCreditCard $false)) -Remediate:$Remediate
  $items.Add($r) | Out-Null

  $r = Set-RegValueProof -Product 'Edge' -Area 'Core' -Policy 'SyncDisabled' -Path $base -Name 'SyncDisabled' -Type DWord -Value ([int](Get-BoolDefault $EdgeCfg.SyncDisabled $true)) -Remediate:$Remediate
  $items.Add($r) | Out-Null

  $sslMin = Get-TextOrNull $EdgeCfg.SSLVersionMin
  if (-not $sslMin) { $sslMin = 'tls1.2' }
  $r = Set-RegValueProof -Product 'Edge' -Area 'Security' -Policy 'SSLVersionMin' -Path $base -Name 'SSLVersionMin' -Type String -Value $sslMin -Remediate:$Remediate
  $items.Add($r) | Out-Null

  $tpMap = @{ 'Basic'=1; 'Balanced'=2; 'Strict'=3 }
  $tpKey = Get-TextOrNull $EdgeCfg.TrackingPrevention
  if (-not $tpKey) { $tpKey = 'Balanced' }
  $tp = 2
  foreach($k in $tpMap.Keys) { if ($k -ieq $tpKey) { $tp = $tpMap[$k] } }

  $r = Set-RegValueProof -Product 'Edge' -Area 'Privacy' -Policy 'TrackingPrevention' -Path $base -Name 'TrackingPrevention' -Type DWord -Value $tp -Remediate:$Remediate
  $items.Add($r) | Out-Null

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

  $urlsKey     = Join-Path $base 'RestoreOnStartupURLs'
  $desiredUrls = Get-ArrayStrings $EdgeCfg.StartupURLs

  if ($Remediate) {
    Ensure-Key -Path $urlsKey

    try {
      $p = Get-ItemProperty -Path $urlsKey -ErrorAction SilentlyContinue
      if ($p) {
        foreach($prop in $p.PSObject.Properties) {
          if ($prop.Name -match '^\d+$') {
            Remove-ItemProperty -Path $urlsKey -Name $prop.Name -ErrorAction SilentlyContinue
          }
        }
      }
    } catch {}

    $i = 1
    foreach($u in $desiredUrls) {
      $name     = "$i"
      $expected = [string]$u
      $changed  = $false
      $msg      = $null

      try {
        New-ItemProperty -Path $urlsKey -Name $name -PropertyType String -Value $expected -Force -ErrorAction Stop | Out-Null
        $changed = $true
      } catch {
        $msg = "Write failed: $($_.Exception.Message)"
      }

      $cur = Get-RegValue -Path $urlsKey -Name $name
      $compliant = ($cur -eq $expected)
      if (-not $msg) { $msg = $(if ($compliant -and $changed) { 'Set applied' } elseif (-not $compliant) { 'Set attempted but differs' } else { $null }) }

      $r = New-ProofItem -Product 'Edge' -Area 'Startup' -Policy 'RestoreOnStartupURLs' -Target $urlsKey -Name $name -Type String -Expected $expected -Actual $cur -Compliant $compliant -Changed $changed -Message $msg
      $items.Add($r) | Out-Null
      $i++
    }
  } else {
    $current = @{}
    try {
      $p = Get-ItemProperty -Path $urlsKey -ErrorAction SilentlyContinue
      if ($p) {
        foreach($prop in $p.PSObject.Properties) {
          if ($prop.Name -match '^\d+$') { $current[$prop.Name] = [string]$prop.Value }
        }
      }
    } catch {}

    $want = @{}
    $i = 1
    foreach($u in $desiredUrls) { $want["$i"] = [string]$u; $i++ }

    $allKeys = @($current.Keys + $want.Keys | Select-Object -Unique)
    foreach($k in $allKeys) {
      $expected  = $want[$k]
      $actual    = $current[$k]
      $compliant = ($expected -eq $actual)
      $msg       = $(if (-not $compliant) { 'Drift detected' } else { $null })

      $r = New-ProofItem -Product 'Edge' -Area 'Startup' -Policy 'RestoreOnStartupURLs' -Target $urlsKey -Name $k -Type String -Expected $expected -Actual $actual -Compliant $compliant -Changed $false -Message $msg
      $items.Add($r) | Out-Null
    }
  }

  return $items
}

function Get-FirefoxDistDir {
  [CmdletBinding()]
  param([Parameter(Mandatory)][object]$FirefoxCfg)

  $explicit = Get-TextOrNull $FirefoxCfg.DistributionDir
  if ($explicit) { return $explicit }

  $paths = @(
    "$env:ProgramFiles\Mozilla Firefox\distribution",
    "$env:ProgramFiles(x86)\Mozilla Firefox\distribution"
  )
  foreach($p in $paths) {
    if (Test-Path -LiteralPath (Split-Path -Parent $p)) { return $p }
  }
  return $paths[0]
}

function Build-FirefoxPolicies {
  [CmdletBinding()]
  param([Parameter(Mandatory)][object]$FirefoxCfg)

  $tlsMin = Get-IntDefault $FirefoxCfg.TLSMin 3
  $tp     = Get-TextOrNull $FirefoxCfg.TrackingProtection
  if (-not $tp) { $tp = 'strict' }

  $pol = [ordered]@{
    policies = [ordered]@{
      DisableAppUpdate         = [bool](Get-BoolDefault $FirefoxCfg.DisableAppUpdate $true)
      DisableTelemetry         = [bool](Get-BoolDefault $FirefoxCfg.DisableTelemetry $true)
      DisableFirefoxStudies    = $true
      DisableShield            = $true
      BlockAboutConfig         = $true
      DNSOverHTTPS             = @{ Enabled = $false }
      SearchSuggestEnabled     = $false
      EnableTrackingProtection = $true
      TrackingProtection       = @{ Value = $tp }
      PasswordManagerEnabled   = [bool](Get-BoolDefault $FirefoxCfg.PasswordManagerEnabled $false)
      OfferToSaveLogins        = $false
      OfferToSaveLoginsDefault = $false
      TLSVersionMin            = $tlsMin
      Extensions               = @{}
    }
  }

  $allow = @()
  if ($FirefoxCfg.BlockAllAddonsExcept) { $allow = @($FirefoxCfg.BlockAllAddonsExcept) }

  $install = @()
  if ($FirefoxCfg.InstallAddons) { $install = @($FirefoxCfg.InstallAddons) }

  if ($allow.Count -gt 0) {
    $pol.policies.Extensions = @{
      Install           = @($install)
      ExtensionSettings = @{ "*" = @{ installation_mode = "blocked" } }
    }
    foreach($id in $allow) {
      $id2 = Get-TextOrNull $id
      if ($id2) { $pol.policies.Extensions.ExtensionSettings[$id2] = @{ installation_mode = "allowed" } }
    }
  } elseif ($install.Count -gt 0) {
    $pol.policies.Extensions = @{ Install = @($install) }
  }

  return $pol
}

function Ensure-Firefox {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$FirefoxCfg,
    [switch]$Remediate
  )

  $items = New-Object System.Collections.Generic.List[object]

  $enabled = Get-BoolDefault $FirefoxCfg.Enable $true
  if (-not $enabled) {
    $r = New-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'Enable' -Target 'N/A' -Name 'Enable' -Type String -Expected 'true' -Actual 'false' -Compliant $true -Changed $false -Message 'Skipped (Enable=false)'
    $items.Add($r) | Out-Null
    return $items
  }

  $dist    = Get-FirefoxDistDir -FirefoxCfg $FirefoxCfg
  $polPath = Join-Path $dist 'policies.json'

  $obj     = Build-FirefoxPolicies -FirefoxCfg $FirefoxCfg
  $newJson = $obj | ConvertTo-Json -Depth 20

  $existingRaw = $null
  if (Test-Path -LiteralPath $polPath) {
    try { $existingRaw = Get-Content -Raw -Path $polPath -ErrorAction Stop } catch { $existingRaw = $null }
  }

  $same = $false
  if ($existingRaw) {
    try {
      $existingObj = $existingRaw | ConvertFrom-Json -ErrorAction Stop
      $same = ( ($existingObj | ConvertTo-Json -Depth 20) -eq ($obj | ConvertTo-Json -Depth 20) )
    } catch {
      $same = ($existingRaw -eq $newJson)
    }
  }

  if (-not $same) {
    if ($Remediate) {
      $changed = $false
      $msg     = $null
      try {
        Ensure-Dir -Path $dist
        $utf8NoBOM = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($polPath, $newJson, $utf8NoBOM)
        $changed = $true
        $msg     = 'Wrote policies.json'
      } catch {
        $msg = "Write failed: $($_.Exception.Message)"
      }

      $r = New-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'policies.json' -Target $polPath -Name 'policies.json' -Type File -Expected 'AsBuilt' -Actual $(if($changed){'Written'}else{$null}) -Compliant $changed -Changed $changed -Message $msg
      $items.Add($r) | Out-Null
    } else {
      $r = New-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'policies.json' -Target $polPath -Name 'policies.json' -Type File -Expected 'AsBuilt' -Actual 'Different' -Compliant $false -Changed $false -Message 'Drift detected'
      $items.Add($r) | Out-Null
    }
  } else {
    $r = New-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'policies.json' -Target $polPath -Name 'policies.json' -Type File -Expected 'AsBuilt' -Actual 'Same' -Compliant $true -Changed $false -Message $null
    $items.Add($r) | Out-Null
  }

  $r = New-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'DistributionDir' -Target $dist -Name 'DistributionDir' -Type String -Expected 'Auto/Configured' -Actual $dist -Compliant $true -Changed $false -Message $null
  $items.Add($r) | Out-Null

  return $items
}

# -----------------------------
# Console summary / pretty output
# -----------------------------

function Write-ConsoleSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object[]]$AllItems,
    [Parameter(Mandatory)][object]$CatalogInfo,
    [Parameter(Mandatory)][string]$ProofPath,
    [Parameter(Mandatory)][bool]$IsAdmin,
    [Parameter(Mandatory)][bool]$Remediate,
    [Parameter(Mandatory)][bool]$Strict,
    [Parameter(Mandatory)][string[]]$Notes
  )

  $safe = @($AllItems | ForEach-Object { Ensure-ProofItemLike $_ })

  $officeItems  = @($safe | Where-Object { $_.Product -eq 'Office' })
  $edgeItems    = @($safe | Where-Object { $_.Product -eq 'Edge' })
  $firefoxItems = @($safe | Where-Object { $_.Product -eq 'Firefox' })

  $sum = @(
    New-ResultSummary -Section 'Office'  -Items $officeItems
    New-ResultSummary -Section 'Edge'    -Items $edgeItems
    New-ResultSummary -Section 'Firefox' -Items $firefoxItems
  )

  Write-Host ""
  Write-Host "==================================================" -ForegroundColor DarkCyan
  Write-Host " Office / Browser Hardening Summary" -ForegroundColor Cyan
  Write-Host "==================================================" -ForegroundColor DarkCyan
  Write-Host ("Catalog source : {0}" -f $CatalogInfo.LoadedFrom) -ForegroundColor Gray
  Write-Host ("Mode           : Remediate={0}  Strict={1}  IsAdmin={2}" -f $Remediate, $Strict, $IsAdmin) -ForegroundColor Gray
  Write-Host ""

  foreach($row in $sum) {
    $statusText  = if ($row.Ok) { "OK" } else { "DRIFT" }
    $statusColor = if ($row.Ok) { 'Green' } else { 'Red' }

    Write-Host ("[{0}]" -f $row.Section) -ForegroundColor White -NoNewline
    Write-Host (" {0,-5} " -f $statusText) -ForegroundColor $statusColor -NoNewline
    Write-Host ("Total={0}  NonCompliant={1}  Changed={2}" -f $row.Total, $row.NonCompliant, $row.Changed) -ForegroundColor Gray
  }

  $driftSample = @($safe | Where-Object { (Bool-Prop $_ 'Compliant' $true) -eq $false } | Select-Object -First 10)
  if ($driftSample.Count -gt 0) {
    Write-Host ""
    Write-Host "Drift sample (first 10 items)" -ForegroundColor Yellow
    Write-Host "---------------------------------------------" -ForegroundColor DarkYellow
    foreach($d in $driftSample) {
      Write-Host ("- [{0}/{1}] {2} :: {3}\{4} (Expected={5} Actual={6})" -f $d.Product, $d.Area, $d.Policy, $d.Target, $d.Name, $d.Expected, $d.Actual) -ForegroundColor Yellow
    }
  }

  if ($Notes -and $Notes.Count -gt 0) {
    Write-Host ""
    Write-Host "Notes" -ForegroundColor White
    Write-Host "-----" -ForegroundColor White
    foreach($n in $Notes) { Write-Host ("- " + $n) -ForegroundColor DarkGray }
  }

  Write-Host ""
  Write-Host ("Proof JSON written to: {0}" -f $ProofPath) -ForegroundColor Cyan
  Write-Host ""

  $total        = $safe.Count
  $nonCompliant = @($safe | Where-Object { (Bool-Prop $_ 'Compliant' $true) -eq $false }).Count
  $changed      = @($safe | Where-Object { (Bool-Prop $_ 'Changed' $false) -eq $true }).Count

  $overallOk  = ($nonCompliant -eq 0)
  $finalColor = if ($overallOk -and -not $Strict) { 'Green' } else { 'Red' }
  $finalText  = if ($overallOk -and -not $Strict) { 'HARDENING OK' } else { 'DRIFT DETECTED' }

  Write-Host "==================================================" -ForegroundColor DarkCyan
  Write-Host (" Final result : {0}" -f $finalText) -ForegroundColor $finalColor
  Write-Host (" Items        : Total={0}  NonCompliant={1}  Changed={2}" -f $total, $nonCompliant, $changed) -ForegroundColor Gray
  Write-Host "==================================================" -ForegroundColor DarkCyan

  Write-Information ("Summary: FinalResult={0}; Total={1}; NonCompliant={2}; Changed={3}" -f $finalText, $total, $nonCompliant, $changed)
}

# -----------------------------
# Main
# -----------------------------

Ensure-EventSource -Source $EventSource -Log $EventLog

$isAdmin     = Is-Admin
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
  Save-Json -Obj $proof -Path $proofPath
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
  # ignore event log failures
}

Write-ConsoleSummary -AllItems @($allSafe) -CatalogInfo $catalogInfo -ProofPath $proofPath -IsAdmin $isAdmin -Remediate ([bool]$Remediate) -Strict ([bool]$Strict) -Notes @($globalNotes)

# $allSafe

if (-not $overallOk -or $Strict) { exit 1 } else { exit 0 }
