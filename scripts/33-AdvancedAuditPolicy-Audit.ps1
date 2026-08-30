#Requires -RunAsAdministrator
#requires -version 5.1
<#
.SYNOPSIS
Audits Advanced Audit Policy (subcategories) via auditpol.exe, detects common misconfigurations,
optionally compares against a desired-state JSON and can remediate.

.DESCRIPTION
- Pipeline output: single structured object (Summary, Findings, ParsedPolicies).
- Console output: formatted blocks via Write-UiLine only.
- Desired policy:
  - If JSON is missing/unreadable/invalid => built-in defaults are used for drift checks only.
  - Remediate requires a valid JSON file.
- PowerShell 5.1 safe: avoids Generic.List binder edge-cases.

.PARAMETER Mode
Audit | Remediate

.PARAMETER DesiredPolicyJson
Path to JSON with desired subcategory settings supplied with $DesiredPolicyJson.

.PARAMETER ExportPath
Optional base path for CSV export. Creates: *_summary.csv, *_findings.csv, *_policies.csv

.PARAMETER ConfigPath
  Path to JSON configuration file.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER PassThru
  Emit structured v2 result object to pipeline.

.PARAMETER Strict
  Treat warnings as failures.

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.


.OUTPUTS
  None by default.
  When -PassThru is used, emits a PSCustomObject v2 result with Script, Mode, Result, Findings, Summary, and Metadata properties.

.EXAMPLE
  .\33-AdvancedAuditPolicy-Audit.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('Audit','Remediate')]
  [string]$Mode = 'Audit',

  [string]$DesiredPolicyJson,

  [string]$ExportPath

,
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '33-AdvancedAuditPolicy-Audit.ps1' -BoundParameters $PSBoundParameters `
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
  $result = Get-V2ResultObject -ScriptName '33-AdvancedAuditPolicy-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$script:Findings = Get-FindingsList

# -------------------- Helpers --------------------


# Get-FindingStats imported from lib/Console.psm1

function Get-AuditPolText {
  # Use /r flag for CSV output (locale-independent)
  $r = Invoke-Auditpol -Arguments @('/get', '/category:*', '/r') -CaptureOutput
  if ($null -eq $r) { throw 'auditpol did not return a process result.' }
  if ($r.TimedOut) { throw 'auditpol evidence query timed out.' }
  if ($r.OutputTruncated -or $r.StderrTruncated) { throw 'auditpol evidence query produced truncated output.' }
  if (-not $r.Success) { throw "auditpol exited with code $($r.ExitCode)." }
  if ([string]::IsNullOrWhiteSpace([string]$r.Stdout)) { throw 'auditpol evidence query returned no CSV output.' }
  return [string]$r.Stdout
}

function Parse-AuditPolText {
  param([Parameter(Mandatory=$true)][string]$Text)

  # Return policies as object[] (arrays behave best in PS pipeline and serializers).
  $policies = @()

  if ([string]::IsNullOrWhiteSpace($Text)) { throw 'auditpol CSV is empty.' }

  # Parse CSV output from auditpol /get /category:* /r (locale-independent)
  $lines = @($Text -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($lines.Count -lt 2) { throw 'auditpol CSV has no data rows.' }

  $csvRows = @($lines | ConvertFrom-Csv -ErrorAction Stop)
  $seenGuids = @{}
  $seenSubcategories = @{}
  foreach ($row in $csvRows) {
    # /r has a stable six-column order even when display headers are localized:
    # machine, target, subcategory, subcategory GUID, inclusion, exclusion.
    $properties = @($row.PSObject.Properties)
    if ($properties.Count -lt 6) { throw 'auditpol CSV row has fewer than six columns.' }
    $sub = [string]$properties[2].Value
    $guidText = [string]$properties[3].Value
    $set = [string]$properties[4].Value
    $guid = [guid]::Empty
    if ([string]::IsNullOrWhiteSpace($sub) -or [string]::IsNullOrWhiteSpace($set) -or -not [guid]::TryParse($guidText, [ref]$guid)) {
      throw 'auditpol CSV contains an invalid subcategory, GUID, or inclusion setting.'
    }
    $guidKey = $guid.ToString('D')
    if ($seenGuids.ContainsKey($guidKey) -or $seenSubcategories.ContainsKey($sub)) {
      throw 'auditpol CSV contains duplicate subcategory evidence.'
    }
    $seenGuids[$guidKey] = $true
    $seenSubcategories[$sub] = $true
    $policies += [pscustomobject]@{
      Category        = '(NotReported)'
      Subcategory     = $sub
      SubcategoryGuid = $guidKey
      Setting         = $set
    }
  }

  if ($policies.Count -lt 10) { throw 'auditpol CSV contains too few policy rows to be complete.' }

  $policies
}

function Convert-DesiredSettingToFlags {
  param([Parameter(Mandatory=$true)][string]$SettingString)

  $success = $false
  $failure = $false

  switch -Regex ($SettingString.Trim()) {
    '^Success and Failure$' { $success = $true;  $failure = $true;  break }
    '^Success$'             { $success = $true;  $failure = $false; break }
    '^Failure$'             { $success = $false; $failure = $true;  break }
    '^No Auditing$'         { $success = $false; $failure = $false; break }
    default { throw "Unknown setting string: '$SettingString'. Allowed: 'Success', 'Failure', 'Success and Failure', 'No Auditing'." }
  }

  [pscustomobject]@{ Success = $success; Failure = $failure }
}

function Get-DefaultDesiredPolicy {
  # Defaults are intentionally minimal: safe drift checks even without JSON.
  $json = @'
{
  "Logon/Logoff": {
    "Logon": "Success and Failure",
    "Special Logon": "Success"
  },
  "Account Logon": {
    "Kerberos Service Ticket Operations": "Failure",
    "Kerberos Authentication Service": "Failure"
  },
  "Policy Change": {
    "Audit Policy Change": "Success and Failure"
  }
}
'@
  $json | ConvertFrom-Json
}

function Try-ReadDesiredPolicyJson {
  param([string]$Path)

  $sanitized = Sanitize-Path -Path $Path -MustExist
  if (-not $sanitized) {
    return [pscustomobject]@{ Desired = $null; Source = 'Missing'; Error = "DesiredPolicyJson not found or invalid: $Path" }
  }

  try {
    $desired = Get-BoundedUtf8FileContent -Path $sanitized -MaximumBytes 1048576 | ConvertFrom-Json
    if ($null -eq $desired -or $desired -isnot [psobject]) { throw "Invalid JSON root object." }

    # Validate values up-front (prevents remediation surprises).
    foreach ($catProp in $desired.PSObject.Properties) {
      if ($null -eq $catProp.Value -or $catProp.Value -isnot [psobject]) {
        throw "Invalid JSON: category '$($catProp.Name)' is not an object."
      }
      foreach ($subProp in $catProp.Value.PSObject.Properties) {
        $val = [string]$subProp.Value
        if ([string]::IsNullOrWhiteSpace($val)) {
          throw "Invalid JSON: empty setting for '$($catProp.Name) -> $($subProp.Name)'."
        }
        [void](Convert-DesiredSettingToFlags -SettingString $val)
      }
    }

    return [pscustomobject]@{ Desired = $desired; Source = 'Json'; Error = $null }
  }
  catch {
    return [pscustomobject]@{ Desired = $null; Source = 'Invalid'; Error = $_.Exception.Message }
  }
}

# -------------------- Console UI (Write-ConsoleSummary / Get-SeverityColor from lib/Console.psm1) --------------------

function Write-FindingsConsole {
  param([Parameter(Mandatory=$true)][System.Collections.IList]$Findings)

  Write-DecorativeRule -Title ("Findings ({0})" -f $Findings.Count)

  if ($Findings.Count -eq 0) {
    Write-UiLine 'No findings.' -ForegroundColor Green
    return
  }

  $order = @('High','Medium','Low','Info')
  foreach ($sev in $order) {
    $items = @($Findings | Where-Object { $_.Severity -eq $sev })
    if ($items.Count -eq 0) { continue }

    $color = Get-SeverityColor -Severity $sev
    Write-UiLine ("{0} ({1})" -f $sev.ToUpperInvariant(), $items.Count) -ForegroundColor $color

    foreach ($f in $items) {
      Write-UiLine ("  [{0}] {1}" -f $f.Code, $f.Message) -ForegroundColor $color
    }

    Write-UiLine ''
  }
}

# -------------------- Main --------------------

Require-Admin
Ensure-Exe -Name 'auditpol.exe'

$auditEvidenceComplete = $true
$policies = @()
try {
  $txt = Get-AuditPolText
  $policies = Parse-AuditPolText -Text $txt
} catch {
  $auditEvidenceComplete = $false
  Add-Finding -FindingList $script:Findings -Code 'AUD-EvidenceIncomplete' -Severity 'High' -Message ("Audit policy evidence is incomplete: {0}" -f $_.Exception.Message)
}

if ($policies.Count -eq 0) {
  Add-Finding -FindingList $script:Findings -Code 'AUD-ParserEmpty' -Severity 'High' -Message 'Parsed 0 audit policies. Check parser/locale/Windows version.'
}

# Basic audit checks.
$mustHave = @(
  @{ CategoryLike='Logon*';         SubLike='Logon';               Severity='High';   Code='AUD-LogonOff';         Message='Logon auditing is disabled (No Auditing).' },
  @{ CategoryLike='Account Logon*'; SubLike='Kerberos*';           Severity='Medium'; Code='AUD-KerberosOff';      Message='Kerberos auditing is disabled (No Auditing).' },
  @{ CategoryLike='Policy Change*'; SubLike='Audit Policy Change'; Severity='Low';    Code='AUD-PolicyChangeOff'; Message='Audit Policy Change is disabled (No Auditing).' }
)

foreach ($m in $mustHave) {
  $hit = $policies | Where-Object { $_.Subcategory -like $m.SubLike } | Select-Object -First 1
  if ($hit) {
    if ([string]$hit.Setting -match 'No Auditing') {
      Add-Finding -FindingList $script:Findings -Code $m.Code -Severity $m.Severity -Message ("{0} Category='{1}', Subcategory='{2}', Setting='{3}'." -f $m.Message, $hit.Category, $hit.Subcategory, $hit.Setting)
    }
  } else {
    Add-Finding -FindingList $script:Findings -Code 'AUD-ParserMiss' -Severity 'High' -Message ("Required audit subcategory is missing from complete evidence: {0}" -f $m.SubLike)
  }
}

# Desired policy (JSON or defaults).
$desiredInfo   = Try-ReadDesiredPolicyJson -Path $DesiredPolicyJson
$desired       = $desiredInfo.Desired
$desiredSource = $desiredInfo.Source
$desiredError  = $desiredInfo.Error

if (-not $desired) {
  $desired = Get-DefaultDesiredPolicy
  $desiredSource = if ($desiredSource -eq 'None') { 'Default' } else { ("{0} -> Default" -f $desiredSource) }

  if ($desiredError) {
    Add-Finding -FindingList $script:Findings -Code 'AUD-DesiredPolicyFallback' -Severity 'Info' -Message ("DesiredPolicyJson could not be loaded; using defaults. Error: {0}" -f $desiredError)
  } else {
    Add-Finding -FindingList $script:Findings -Code 'AUD-DesiredPolicyDefault' -Severity 'Info' -Message 'No DesiredPolicyJson provided; using built-in defaults for drift checks.'
  }
}

# Drift checks.
foreach ($catProp in $desired.PSObject.Properties) {
  $catName = $catProp.Name
  $subsObj = $catProp.Value

  foreach ($subProp in $subsObj.PSObject.Properties) {
    $subName = $subProp.Name
    $wanted  = [string]$subProp.Value

    $current = $policies | Where-Object { $_.Subcategory -eq $subName } | Select-Object -First 1
    if (-not $current) {
      Add-Finding -FindingList $script:Findings -Code 'AUD-DesiredNotFound' -Severity 'High' -Message ("Desired policy has '{0} -> {1}', but it was not found in auditpol output." -f $catName, $subName)
      continue
    }

    if ([string]$current.Setting -ne $wanted) {
      Add-Finding -FindingList $script:Findings -Code 'AUD-Drift' -Severity 'Medium' -Message ("Drift: '{0} -> {1}' is '{2}', expected '{3}'." -f $catName, $subName, $current.Setting, $wanted) -Extra @{ Category = $catName; Subcategory = $subName; Current = $current.Setting; Desired = $wanted }
    }
  }
}

# Remediation: only with valid JSON (never with defaults).
if ($Mode -eq 'Remediate') {
  if (-not $auditEvidenceComplete) {
    $msg = 'Mode=Remediate requires complete pre-remediation audit policy evidence.'
    Add-Finding -FindingList $script:Findings -Code 'AuditPol-IncompletePrecondition' -Severity 'Critical' -Message $msg
    $v2Result = Get-V2ResultObject -ScriptName '33-AdvancedAuditPolicy-Audit.ps1' -Mode $Mode -Result 'FAIL' -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary @{ Error = $msg } -Metadata @{}
    Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
    if ($PassThru) { $v2Result }
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  if ($desiredInfo.Source -ne 'Json') {
    $msg = 'Mode=Remediate requires a readable file passed with -DesiredPolicyJson; built-in defaults cannot be remediated.'
    Write-Warning $msg
    Add-Finding -FindingList $script:Findings -Code 'AuditPol-NoDesiredPolicy' -Severity 'Critical' -Message $msg
    $v2Result = Get-V2ResultObject -ScriptName '33-AdvancedAuditPolicy-Audit.ps1' -Mode $Mode -Result 'FAIL' -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary @{ Error = $msg } -Metadata @{}
    Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
    if ($PassThru) { $v2Result }
    exit (Get-V2ExitCode -Result 'FAIL')
  }

  foreach ($catProp in $desired.PSObject.Properties) {
    $subsObj = $catProp.Value

    foreach ($subProp in $subsObj.PSObject.Properties) {
      $subName   = $subProp.Name
      $setWanted = [string]$subProp.Value

      # S6 fix: validate subcategory name to prevent argument injection via auditpol.exe
      if ($subName -notmatch '^[a-zA-Z0-9 \-\/]+$') {
        Add-Finding -FindingList $script:Findings -Code 'AuditPol-InvalidSubcategory' -Severity 'High' -Message ("Subcategory name contains invalid characters, skipped: {0}" -f $subName)
        continue
      }

      $flags      = Convert-DesiredSettingToFlags -SettingString $setWanted
      $successArg = if ($flags.Success) { '/success:enable' } else { '/success:disable' }
      $failureArg = if ($flags.Failure) { '/failure:enable' } else { '/failure:disable' }

      # auditpol /set syntax [page:1]
      $operation = ('auditpol.exe /set /subcategory:"{0}" {1} {2}' -f $subName, $successArg, $failureArg)
      if ($PSCmdlet.ShouldProcess($subName, $operation)) {
        $auditArgs = @('/set', "/subcategory:`"$subName`"", $successArg, $failureArg)
        $res = Invoke-Auditpol -Arguments $auditArgs
        if ($res -ne $true) {
          Add-Finding -FindingList $script:Findings -Code 'AuditPol-SetFailed' -Severity 'High' -Message ("auditpol /set failed for subcategory: {0}" -f $subName)
        }
      }
    }
  }

  try {
    $txt = Get-AuditPolText
    $policies = Parse-AuditPolText -Text $txt
    foreach ($catProp in $desired.PSObject.Properties) {
      foreach ($subProp in $catProp.Value.PSObject.Properties) {
        $verified = $policies | Where-Object { $_.Subcategory -eq $subProp.Name } | Select-Object -First 1
        if (-not $verified -or [string]$verified.Setting -ne [string]$subProp.Value) {
          Add-Finding -FindingList $script:Findings -Code 'AuditPol-PostconditionFailed' -Severity 'High' -Message ("Post-remediation policy mismatch: {0} -> {1}." -f $catProp.Name,$subProp.Name)
        }
      }
    }
  } catch {
    $auditEvidenceComplete = $false
    Add-Finding -FindingList $script:Findings -Code 'AUD-PostRemediationEvidenceIncomplete' -Severity 'High' -Message ("Post-remediation audit evidence is incomplete: {0}" -f $_.Exception.Message)
  }
}

# Summary object (materialized primitives to keep StrictMode and serialization safe).
$summary = [pscustomobject]@{
  ComputerName   = [string]$env:COMPUTERNAME
  Mode           = [string]$Mode
  PoliciesParsed = [int]$policies.Count
  FindingsCount  = [int]$script:Findings.Count
  Timestamp      = [datetime](Get-Date)
  DesiredPolicy  = [string]$desiredSource
}

# Optional export.
if ($ExportPath) {
  $dir = Split-Path -Path $ExportPath -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
  }

  $base   = [IO.Path]::GetFileNameWithoutExtension($ExportPath)
  $folder = Split-Path -Path $ExportPath -Parent
  if (-not $folder) { $folder = (Get-Location).Path }

  $summary               | Export-Csv -Path (Join-Path $folder ($base + "_summary.csv"))   -NoTypeInformation -Encoding UTF8
  @($script:Findings)    | Export-Csv -Path (Join-Path $folder ($base + "_findings.csv"))  -NoTypeInformation -Encoding UTF8
  $policies              | Export-Csv -Path (Join-Path $folder ($base + "_policies.csv"))  -NoTypeInformation -Encoding UTF8
}

# Formatted console output (does not write to the pipeline).
$customFields = [ordered]@{
  'Mode'          = $summary.Mode
  'Parsed'        = [string]$summary.PoliciesParsed
  'DesiredPolicy' = $desiredSource
}
if ($desiredError) { $customFields['PolicyError'] = $desiredError }
Write-ConsoleSummary -Summary $summary -Findings $script:Findings `
  -Title 'Advanced Audit Policy - Summary' `
  -CustomFields $customFields
Write-FindingsConsole -Findings $script:Findings

# V2 output contract
$resultToken = if (-not $auditEvidenceComplete) { 'FAIL' } elseif ($Strict -and $script:Findings.Count -gt 0) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '33-AdvancedAuditPolicy-Audit.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $summary -Metadata @{ ParsedPolicies = $policies }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
