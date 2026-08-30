#requires -version 5.1
<#
.SYNOPSIS
  Audits and optionally enforces secure “remote access guardrails” on a Windows endpoint by aligning RDP, Remote Assistance, Windows Firewall, and local group membership to a defined policy.
.DESCRIPTION
  This script implements an audit-first approach for remote access hardening.
  It evaluates the local system against a policy (“catalog”) and produces:
  - Console output with colored status and readable lists.
  - A structured result object on the pipeline (for automation and reporting).
  - A JSON proof file containing the same structured results.
  - An Application event log entry summarizing compliance and actions.
  Policy input is taken from a JSON catalog. If no catalog is provided or loading fails, the script uses built-in safe defaults.
  Guardrail areas:
  - RDP configuration (registry-based): enable/disable, NLA, security layer, encryption level, RDP port, Restricted Admin, password saving policy.
  - Windows Defender Firewall: disables local built-in “Remote Desktop” inbound rules and enforces scoped local inbound rules for RDP (TCP; optional UDP behavior).
  - Local group “Remote Desktop Users”: enforces an allowlist (optionally exact membership), always keeping BUILTIN\Administrators.
  - Remote Assistance (policy registry): enable/disable solicited/unsolicited assistance and ticket lifetime.
  Running with the default `-Mode Audit` performs an audit only (no changes). With `-Mode Remediate`, the script attempts to apply changes to reach the desired state.
.PARAMETER CatalogPath
  Optional path to a policy catalog JSON file.
  If provided and valid, the script uses this catalog as the desired-state definition.
  If omitted or invalid/unreadable, the script falls back to:
  1) A CatalogPath value in the optional config JSON (ConfigPath), if present and valid.
  2) Built-in default policy values.
.PARAMETER ConfigPath
  Optional path to a config JSON file that may reference a catalog path (for example: .RDP.CatalogPath).
  This parameter is used only when CatalogPath is not provided or cannot be loaded.
.PARAMETER ProofPath
  Path to the JSON proof file written at the end of execution.
  The proof file contains a structured object that mirrors the pipeline output (timestamp, host identity, drift, changes, notes, etc.).
  The parent directory is created if it does not exist.
.PARAMETER Strict
  Controls event severity rules.
  If set:
  - Any detected drift results in an “attention” event (EventId 4850).
  If not set:
  - Only execution errors or failed remediation attempts cause EventId 4850.
  - Pure audit drift may still be reported, but can remain informational.
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
  One PSCustomObject (exactly one object is written to the pipeline), containing:
  - TimestampUtc (string): UTC timestamp in ISO 8601 format.
  - ComputerName (string): Local computer name.
  - User (string): User account running the script.
  - Elevated (bool): Whether the script detected an elevated session.
  - Remediate (bool): Whether remediation mode was requested.
  - Strict (bool): Whether strict mode was requested.
  - CatalogPath (string): A configured-path label when a catalog path was provided; otherwise null.
  - ConfigPath (string): A configured-path label when a config path was provided; otherwise null.
  - ProofPath (string): Proof file path.
  - Changed (string[]): Human-readable list of successful changes applied.
  - Drift (string[]): Human-readable list of detected drift and/or remediation failures.
  - Notes (string[]): Additional operational notes (e.g., non-elevated run, proof write issues).
  - EventId (int): Event ID written to the Application log (4840 informational / 4850 attention).
  - HasError (bool): True if a fatal error occurred or proof writing failed.
  - HasDrift (bool): True if drift was detected.
  The output object is designed for:
  - Export-Csv
  - ConvertTo-Json
  - Where-Object filtering
  without being polluted by console formatting output.
.EXAMPLE
  .\14-SecureRemoteAccessGuardrails.ps1
  Runs an audit only using the configured catalog or built-in defaults.
  Writes a console summary, event log entry, proof JSON, and emits one result object.
.EXAMPLE
  .\14-SecureRemoteAccessGuardrails.ps1 -CatalogPath $CatalogPath
  Runs an audit using an explicit policy catalog file.
.EXAMPLE
  .\14-SecureRemoteAccessGuardrails.ps1 -Mode Remediate -WhatIf
  Shows which changes would be applied to enforce the desired state, without making changes.
.EXAMPLE
  .\14-SecureRemoteAccessGuardrails.ps1 -Mode Remediate -Confirm
  Prompts before applying enforcement changes.
.EXAMPLE
  $r = .\14-SecureRemoteAccessGuardrails.ps1 -Mode Remediate
  $r | Where-Object HasError -eq $true
  Runs remediation and filters results in an automation-friendly way using the pipeline output.
.EXAMPLE
  .\14-SecureRemoteAccessGuardrails.ps1 -Strict | ConvertTo-Json -Depth 6
  Runs in strict mode (drift is treated as attention) and prints the result object as JSON.
.NOTES
  Safety and operational guidance:
  - Remediation can disable or restrict remote access; run with -WhatIf first and ensure console access is available.
  - Remediation may require elevation; audit can still run without elevation but changes may fail.
  - The script intentionally keeps console output separate from pipeline output for reliable automation.
  - The script writes a proof JSON file for compliance evidence and troubleshooting.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [string]$CatalogPath,
  [switch]$Strict,
  [string]$ConfigPath,
  [string]$ProofPath
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
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'JsonCatalog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '14-SecureRemoteAccessGuardrails.ps1' -BoundParameters $PSBoundParameters `
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
  $result = Get-V2ResultObject -ScriptName '14-SecureRemoteAccessGuardrails.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$script:Findings = Get-FindingsList
if ([string]::IsNullOrWhiteSpace($ProofPath)) {
  $ProofPath = Join-Path ([System.IO.Path]::GetTempPath()) 'SecureRemoteAccessGuardrails-proof.json'
}
# ----------------------------
# Constants / defaults
# ----------------------------
$ScriptEventSource = "SecureRemoteAccessGuardrails"
$ScriptEventLog    = "Application"
$DefaultCatalogJson = @"
{
  "RDP": {
    "Enable": false,
    "Port": 3389,
    "Profiles": [ "Domain" ],
    "RemoteAddresses": [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" ],
    "AllowUDP": false,
    "NLA": true,
    "SecurityLayer": "TLS",
    "MinEncryptionLevel": "High",
    "RestrictedAdmin": true,
    "DisablePasswordSaving": true,
    "EnforceGroupMembership": true,
    "AllowedGroups": [ "DOMAIN\\RDP-Admins" ],
    "ExactMembership": true
  },
  "RemoteAssistance": {
    "AllowSolicited": false,
    "AllowUnsolicited": false,
    "Helpers": [],
    "TicketMaxLifetimeMinutes": 60
  }
}
"@
# ----------------------------
# UI helpers (console only)
# ----------------------------
# ----------------------------
# Generic helpers (no console formatting here)
# ----------------------------
function Test-IsElevated {
  try {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
      IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}
# Ensure-DirectoryForFile imported from lib/Common.psm1
function Normalize-Array {
  param([object]$Value)
  if ($null -eq $Value) { return @() }
  if ($Value -is [Array]) { return @($Value | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
  return @("$Value".Trim()) | Where-Object { $_ }
}
function ConvertFrom-JsonSafe {
  param([string]$JsonText)
  try { return ($JsonText | ConvertFrom-Json -ErrorAction Stop) }
  catch { return $null }
}
function Get-DefaultCatalog {
  $c = ConvertFrom-JsonSafe -JsonText $DefaultCatalogJson
  if ($c) { return $c }
  throw "Built-in default catalog JSON is invalid."
}
function Merge-CatalogWithDefaults {
  param(
    [psobject]$Catalog,
    [psobject]$Defaults
  )
  if (-not $Catalog) { return $Defaults }
  if (-not $Catalog.RDP) { $Catalog | Add-Member -NotePropertyName RDP -NotePropertyValue ([pscustomobject]@{}) -Force }
  if (-not $Catalog.RemoteAssistance) { $Catalog | Add-Member -NotePropertyName RemoteAssistance -NotePropertyValue ([pscustomobject]@{}) -Force }
  foreach ($p in @('Enable','Port','Profiles','RemoteAddresses','AllowUDP','NLA','SecurityLayer','MinEncryptionLevel','RestrictedAdmin','DisablePasswordSaving','EnforceGroupMembership','AllowedGroups','ExactMembership')) {
    if ($null -eq $Catalog.RDP.$p) { $Catalog.RDP | Add-Member -NotePropertyName $p -NotePropertyValue $Defaults.RDP.$p -Force }
  }
  foreach ($p in @('AllowSolicited','AllowUnsolicited','Helpers','TicketMaxLifetimeMinutes')) {
    if ($null -eq $Catalog.RemoteAssistance.$p) { $Catalog.RemoteAssistance | Add-Member -NotePropertyName $p -NotePropertyValue $Defaults.RemoteAssistance.$p -Force }
  }
  return $Catalog
}
function Load-Catalog {
  param([string]$ExplicitCatalogPath,[string]$ConfigPath)
  $defaults = Get-DefaultCatalog
  $cat = Read-JsonFileSafe -Path $ExplicitCatalogPath
  if ($cat) { return (Merge-CatalogWithDefaults -Catalog $cat -Defaults $defaults) }
  $cfg = Read-JsonFileSafe -Path $ConfigPath
  if ($cfg -and $cfg.RDP -and $cfg.RDP.CatalogPath) {
    $cat2 = Read-JsonFileSafe -Path ([string]$cfg.RDP.CatalogPath)
    if ($cat2) { return (Merge-CatalogWithDefaults -Catalog $cat2 -Defaults $defaults) }
  }
  return $defaults
}
function Compare-FwMultiValue {
  param([object]$Actual,[string[]]$Expected)
  $a = (Normalize-Array -Value $Actual) | Sort-Object -Unique
  $e = (Normalize-Array -Value $Expected) | Sort-Object -Unique
  return (@($a) -join ',') -eq (@($e) -join ',')
}
function Test-CmdletAvailable {
  param([string]$Name)
  try { return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue) }
  catch { return $false }
}
# ----------------------------
# Firewall (local PersistentStore only)
# ----------------------------
function Get-LocalFirewallRuleByDisplayName {
  param([string]$DisplayName)
  try { return Get-NetFirewallRule -PolicyStore PersistentStore -DisplayName $DisplayName -ErrorAction SilentlyContinue }
  catch { return $null }
}
function Remove-LocalFirewallRuleByDisplayName {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([string]$DisplayName)
  try {
    $r = Get-LocalFirewallRuleByDisplayName -DisplayName $DisplayName
    if ($r -and $PSCmdlet.ShouldProcess($DisplayName, 'Remove local firewall rule')) {
      $r | Remove-NetFirewallRule -ErrorAction Stop | Out-Null
    }
    return $true
  } catch { return $false }
}
function Disable-LocalBuiltinRdpInbound {
  try {
    $rules = Get-NetFirewallRule -PolicyStore PersistentStore -DisplayGroup 'Remote Desktop' -Direction Inbound -ErrorAction Stop
    foreach ($r in @($rules)) {
      try { $r | Disable-NetFirewallRule -ErrorAction Stop | Out-Null } catch {
        Write-Verbose ("Built-in RDP firewall rule disable failed for '{0}': {1}" -f $r.Name,$_.Exception.Message)
      }
    }
  } catch {
    Write-Verbose ("Built-in RDP firewall rule enumeration failed: {0}" -f $_.Exception.Message)
  }
}
function Get-RdpFirewallSettings {
  param([Parameter(Mandatory)][psobject]$Rdp)
  $profiles = Normalize-Array -Value $Rdp.Profiles
  if (@($profiles).Count -eq 0) { $profiles = @('Domain') }
  $scope = Normalize-Array -Value $Rdp.RemoteAddresses
  if (@($scope).Count -eq 0) { $scope = @('LocalSubnet') }
  $port = 3389
  try { if ($Rdp.Port) { $port = [int]$Rdp.Port } } catch { $port = 3389 }
  $messages = @()
  if ($port -lt 1 -or $port -gt 65535) { $port = 3389; $messages += 'Invalid RDP.Port in catalog; using 3389.' }
  $allowUdp = $false
  try { if ($null -ne $Rdp.AllowUDP) { $allowUdp = [bool]$Rdp.AllowUDP } } catch { $allowUdp = $false }
  return [pscustomobject]@{ Profiles = $profiles; Scope = $scope; Port = $port; AllowUdp = $allowUdp; Messages = $messages }
}
function New-RdpFirewallRule {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][string]$DisplayName,
    [Parameter(Mandatory)][string]$Action,
    [Parameter(Mandatory)][string]$Protocol,
    [Parameter(Mandatory)][int]$Port,
    [Parameter(Mandatory)][string[]]$Profiles,
    [Parameter(Mandatory)][string[]]$RemoteAddress,
    [Parameter(Mandatory)][string]$Group
  )
  if (-not $PSCmdlet.ShouldProcess('Firewall', "Create $DisplayName")) { return $false }
  New-NetFirewallRule -PolicyStore PersistentStore -DisplayName $DisplayName -Group $Group `
    -Direction Inbound -Action $Action -Enabled True -Protocol $Protocol -LocalPort $Port `
    -Profile $Profiles -RemoteAddress $RemoteAddress -Service 'TermService' | Out-Null
  return $true
}
function Get-RdpTcpFirewallDrift {
  param([Parameter(Mandatory)]$Rule,[Parameter(Mandatory)]$Settings,[Parameter(Mandatory)][string]$DisplayName)
  $drifts = @()
  $portFilter = $Rule | Get-NetFirewallPortFilter -ErrorAction Stop
  $addressFilter = $Rule | Get-NetFirewallAddressFilter -ErrorAction Stop
  if ($Rule.Enabled -ne 'True') { $drifts += "${DisplayName}: not enabled" }
  if ($Rule.Action -ne 'Allow') { $drifts += "${DisplayName}: action not Allow" }
  if (-not (Compare-FwMultiValue -Actual $Rule.Profile -Expected $Settings.Profiles)) { $drifts += "${DisplayName}: profile drift" }
  if ("$($portFilter.LocalPort)" -ne "$($Settings.Port)") { $drifts += "${DisplayName}: LocalPort $($portFilter.LocalPort) != $($Settings.Port)" }
  if (-not (Compare-FwMultiValue -Actual $addressFilter.RemoteAddress -Expected $Settings.Scope)) { $drifts += "${DisplayName}: RemoteAddress drift" }
  return [pscustomobject]@{ Messages = $drifts; PortFilter = $portFilter; AddressFilter = $addressFilter }
}
function Set-RdpTcpFirewallRule {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([Parameter(Mandatory)]$Rule,[Parameter(Mandatory)]$Settings,[Parameter(Mandatory)][string]$DisplayName)
  if (-not $PSCmdlet.ShouldProcess('Firewall', "Repair $DisplayName")) { return $false }
  $Rule | Set-NetFirewallRule -Enabled True -Action Allow -Profile $Settings.Profiles -ErrorAction Stop | Out-Null
  $Rule | Set-NetFirewallPortFilter -Protocol TCP -LocalPort $Settings.Port -ErrorAction Stop | Out-Null
  $Rule | Set-NetFirewallAddressFilter -RemoteAddress $Settings.Scope -ErrorAction Stop | Out-Null
  return $true
}
function Ensure-RdpUdpFirewallMode {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([Parameter(Mandatory)]$Settings,[Parameter(Mandatory)][string]$AllowName,[Parameter(Mandatory)][string]$BlockName,[Parameter(Mandatory)][string]$Group,[switch]$Remediate)
  $actions = @(); $drifts = @()
  $createName = if ($Settings.AllowUdp) { $AllowName } else { $BlockName }
  $createAction = if ($Settings.AllowUdp) { 'Allow' } else { 'Block' }
  $createRemoteAddress = if ($Settings.AllowUdp) { $Settings.Scope } else { @('Any') }
  if (-not (Get-LocalFirewallRuleByDisplayName -DisplayName $createName)) {
    if ($Remediate) {
      try {
        if (New-RdpFirewallRule -DisplayName $createName -Action $createAction -Protocol UDP -Port $Settings.Port -Profiles $Settings.Profiles -RemoteAddress $createRemoteAddress -Group $Group) { $actions += "Created $createName" }
        else { $drifts += "Missing local rule: $createName" }
      } catch { $drifts += "Failed to create $createName - $($_.Exception.Message)" }
    } else { $drifts += "Missing local rule: $createName" }
  }
  $oppositeName = if ($Settings.AllowUdp) { $BlockName } else { $AllowName }
  $oppositeMode = if ($Settings.AllowUdp) { 'UDP allowed' } else { 'UDP blocked' }
  if ($Remediate) {
    if (Get-LocalFirewallRuleByDisplayName -DisplayName $oppositeName) {
      if (Remove-LocalFirewallRuleByDisplayName -DisplayName $oppositeName) { $actions += "Removed $oppositeName ($oppositeMode)" }
      else { $drifts += "Failed to remove $oppositeName ($oppositeMode)" }
    }
  } elseif (Get-LocalFirewallRuleByDisplayName -DisplayName $oppositeName) {
    $drifts += "$(if ($Settings.AllowUdp) { 'UDP allowed but block rule exists' } else { 'UDP blocked but allow rule exists' }): $oppositeName"
  }
  return [pscustomobject]@{ Actions = $actions; Drifts = $drifts }
}
function Ensure-RdpFirewallRules {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([psobject]$Rdp,[switch]$Remediate)
  $actions = @()
  $drifts  = @()
  if (-not (Test-CmdletAvailable -Name 'Get-NetFirewallRule')) {
    return @("NetSecurity cmdlets not available (Get-NetFirewallRule missing).")
  }
  $settings = Get-RdpFirewallSettings -Rdp $Rdp
  $drifts += $settings.Messages
  $nameTCP      = "Guardrails RDP TCP-In Scoped"
  $nameUDPAllow = "Guardrails RDP UDP-In Scoped"
  $nameUDPBlock = "Guardrails RDP UDP-In Blocked"
  $group        = "Guardrails RDP Scoped"
  # Only disable built-in RDP inbound rules when remediating and catalog specifies RDP disabled (§1/§16)
  if ($Remediate -and -not [bool]$Rdp.Enable) {
    Disable-LocalBuiltinRdpInbound
  }
  if (-not [bool]$Rdp.Enable) {
    if ($Remediate) {
      if (Remove-LocalFirewallRuleByDisplayName -DisplayName $nameTCP)      { $actions += "Removed local rule: $nameTCP" } else { $drifts += "Failed to remove local rule: $nameTCP" }
      if (Remove-LocalFirewallRuleByDisplayName -DisplayName $nameUDPAllow) { $actions += "Removed local rule: $nameUDPAllow" } else { $drifts += "Failed to remove local rule: $nameUDPAllow" }
      if (Remove-LocalFirewallRuleByDisplayName -DisplayName $nameUDPBlock) { $actions += "Removed local rule: $nameUDPBlock" } else { $drifts += "Failed to remove local rule: $nameUDPBlock" }
    } else {
      if (Get-LocalFirewallRuleByDisplayName -DisplayName $nameTCP)      { $drifts += "RDP disabled but local rule exists: $nameTCP" }
      if (Get-LocalFirewallRuleByDisplayName -DisplayName $nameUDPAllow) { $drifts += "RDP disabled but local rule exists: $nameUDPAllow" }
      if (Get-LocalFirewallRuleByDisplayName -DisplayName $nameUDPBlock) { $drifts += "RDP disabled but local rule exists: $nameUDPBlock" }
    }
    return @($actions + $drifts)
  }
  # TCP allow rule
  $ruleTCP = Get-LocalFirewallRuleByDisplayName -DisplayName $nameTCP
  if (-not $ruleTCP) {
    if ($Remediate) {
      try {
        if (New-RdpFirewallRule -DisplayName $nameTCP -Action Allow -Protocol TCP -Port $settings.Port -Profiles $settings.Profiles -RemoteAddress $settings.Scope -Group $group) { $actions += "Created $nameTCP" }
        else { $drifts += "Missing local rule: $nameTCP" }
      } catch {
        $drifts += "Failed to create $nameTCP - $($_.Exception.Message)"
      }
    } else {
      $drifts += "Missing local rule: $nameTCP"
    }
  } else {
    try {
      $tcpDrift = Get-RdpTcpFirewallDrift -Rule $ruleTCP -Settings $settings -DisplayName $nameTCP
      $drifts += $tcpDrift.Messages
      if ($tcpDrift.Messages.Count -gt 0 -and $Remediate) {
        try {
          if (Set-RdpTcpFirewallRule -Rule $ruleTCP -Settings $settings -DisplayName $nameTCP) { $actions += "Repaired $nameTCP" }
        } catch {
          $drifts += "Failed to repair $nameTCP - $($_.Exception.Message)"
        }
      }
    } catch {
      $drifts += "Failed to inspect $nameTCP - $($_.Exception.Message)"
    }
  }
  $udp = Ensure-RdpUdpFirewallMode -Settings $settings -AllowName $nameUDPAllow -BlockName $nameUDPBlock -Group $group -Remediate:$Remediate
  $actions += $udp.Actions; $drifts += $udp.Drifts
  return @($actions + $drifts)
}
# ----------------------------
# Local group enforcement
# ----------------------------
function Ensure-RdpGroupMembership {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([psobject]$Rdp,[switch]$Remediate)
  $actions = @()
  $drifts  = @()
  if (-not [bool]$Rdp.EnforceGroupMembership) { return @() }
  if (-not (Test-CmdletAvailable -Name 'Get-LocalGroupMember')) { return @("LocalAccounts cmdlets not available (Get-LocalGroupMember missing).") }
  $targetGroup = "Remote Desktop Users"
  $allowed     = Normalize-Array -Value $Rdp.AllowedGroups
  $exact       = [bool]$Rdp.ExactMembership
  try {
    $cur = Get-LocalGroupMember -Group $targetGroup -ErrorAction Stop
    $curNames = @($cur | ForEach-Object { $_.Name })
  } catch {
    return @("Cannot read group '$targetGroup' - $($_.Exception.Message)")
  }
  foreach ($a in $allowed) {
    if ($curNames -notcontains $a) {
      if ($Remediate -and $PSCmdlet.ShouldProcess($targetGroup, "Add $a")) {
        try { Add-LocalGroupMember -Group $targetGroup -Member $a -ErrorAction Stop; $actions += "Added member $a" }
        catch { $drifts += "Failed to add member $a - $($_.Exception.Message)" }
      } else {
        $drifts += "Missing member $a"
      }
    }
  }
  if ($exact) {
    $keep = @($allowed + "BUILTIN\Administrators") | Sort-Object -Unique
    foreach ($m in $curNames) {
      if ($keep -notcontains $m) {
        if ($Remediate -and $PSCmdlet.ShouldProcess($targetGroup, "Remove $m")) {
          try { Remove-LocalGroupMember -Group $targetGroup -Member $m -Confirm:$false -ErrorAction Stop; $actions += "Removed member $m" }
          catch { $drifts += "Failed to remove member $m - $($_.Exception.Message)" }
        } else {
          $drifts += "Unexpected member $m"
        }
      }
    }
  }
  return @($actions + $drifts)
}
# ----------------------------
# Remote Assistance enforcement
# ----------------------------
function Ensure-RemoteAssistance {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([psobject]$Ra,[switch]$Remediate)
  $actions = @()
  $drifts  = @()
  $polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
  $wantSol = 0; if ([bool]$Ra.AllowSolicited) { $wantSol = 1 }
  $wantUn  = 0; if ([bool]$Ra.AllowUnsolicited) { $wantUn = 1 }
  $curSol = Get-RegDword -Path $polKey -Name 'fAllowToGetHelp'
  $curUn  = Get-RegDword -Path $polKey -Name 'fAllowUnsolicited'
  if ($curSol -ne $wantSol) {
    if ($Remediate -and $PSCmdlet.ShouldProcess($polKey, "Set fAllowToGetHelp=$wantSol")) {
      if (Set-RegDword -Path $polKey -Name 'fAllowToGetHelp' -Value $wantSol) { $actions += "Set RemoteAssistance fAllowToGetHelp=$wantSol" }
      else { $drifts += "Failed to set RemoteAssistance fAllowToGetHelp=$wantSol" }
    } else {
      $drifts += "RemoteAssistance fAllowToGetHelp $curSol != $wantSol"
    }
  }
  if ($curUn -ne $wantUn) {
    if ($Remediate -and $PSCmdlet.ShouldProcess($polKey, "Set fAllowUnsolicited=$wantUn")) {
      if (Set-RegDword -Path $polKey -Name 'fAllowUnsolicited' -Value $wantUn) { $actions += "Set RemoteAssistance fAllowUnsolicited=$wantUn" }
      else { $drifts += "Failed to set RemoteAssistance fAllowUnsolicited=$wantUn" }
    } else {
      $drifts += "RemoteAssistance fAllowUnsolicited $curUn != $wantUn"
    }
  }
  if ($null -ne $Ra.TicketMaxLifetimeMinutes) {
    $wantTicket = [int]$Ra.TicketMaxLifetimeMinutes
    if ($wantTicket -lt 1) { $wantTicket = 60 }
    $curTicket  = Get-RegDword -Path $polKey -Name 'MaxTicketExpiry'
    if ($curTicket -ne $wantTicket) {
      if ($Remediate -and $PSCmdlet.ShouldProcess($polKey, "Set MaxTicketExpiry=$wantTicket")) {
        if (Set-RegDword -Path $polKey -Name 'MaxTicketExpiry' -Value $wantTicket) { $actions += "Set RemoteAssistance MaxTicketExpiry=$wantTicket" }
        else { $drifts += "Failed to set RemoteAssistance MaxTicketExpiry=$wantTicket" }
      } else {
        $drifts += "RemoteAssistance MaxTicketExpiry $curTicket != $wantTicket"
      }
    }
  }
  return @($actions + $drifts)
}
# ----------------------------
# Main
# ----------------------------
if (-not (Ensure-EventSource -Source $ScriptEventSource -LogName $ScriptEventLog)) {
  Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
}
$start      = Get-Date
$isElevated = Test-IsElevated
$changes = @()
$drifts  = @()
$notes   = @()
$hadError = $false
$resultObject = $null
try {
  if (-not $isElevated) {
    $notes += "Not elevated - audit works, remediation may fail."
    if ($Remediate) { $notes += "Remediate requested but session not elevated." }
  }
  $cat = Load-Catalog -ExplicitCatalogPath $CatalogPath -ConfigPath $ConfigPath
  # Registry keys
  $TSKey     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
  $RdpTcpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
  $LsaKey    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  $PolTSKey  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
  # RDP enable/disable
  $wantEnable = [bool]$cat.RDP.Enable
  $wantDeny   = 1; if ($wantEnable) { $wantDeny = 0 }
  $curDeny    = Get-RegDword -Path $TSKey -Name 'fDenyTSConnections'
  if ($curDeny -ne $wantDeny) {
    if ($Remediate -and $PSCmdlet.ShouldProcess($TSKey, "Set fDenyTSConnections=$wantDeny")) {
      if (Set-RegDword -Path $TSKey -Name 'fDenyTSConnections' -Value $wantDeny) { $changes += "Set fDenyTSConnections=$wantDeny" }
      else { $drifts += "Failed to set fDenyTSConnections=$wantDeny"; $hadError = $true }
    } else { $drifts += "fDenyTSConnections $curDeny != $wantDeny" }
  }
  # NLA
  $wantNLA = 0; if ([bool]$cat.RDP.NLA) { $wantNLA = 1 }
  $curNLA  = Get-RegDword -Path $RdpTcpKey -Name 'UserAuthentication'
  if ($curNLA -ne $wantNLA) {
    if ($Remediate -and $PSCmdlet.ShouldProcess($RdpTcpKey, "Set UserAuthentication=$wantNLA")) {
      if (Set-RegDword -Path $RdpTcpKey -Name 'UserAuthentication' -Value $wantNLA) { $changes += "Set UserAuthentication(NLA)=$wantNLA" }
      else { $drifts += "Failed to set UserAuthentication=$wantNLA"; $hadError = $true }
    } else { $drifts += "UserAuthentication/NLA $curNLA != $wantNLA" }
  }
  # SecurityLayer
  $mapSec = @{ "RDP"=0; "Negotiate"=1; "TLS"=2 }
  $wantSec = 2
  try {
    $secKey = [string]$cat.RDP.SecurityLayer
    if ($secKey -and $mapSec.ContainsKey($secKey)) { $wantSec = [int]$mapSec[$secKey] }
  } catch { $wantSec = 2 }
  $curSec = Get-RegDword -Path $RdpTcpKey -Name 'SecurityLayer'
  if ($curSec -ne $wantSec) {
    if ($Remediate -and $PSCmdlet.ShouldProcess($RdpTcpKey, "Set SecurityLayer=$wantSec")) {
      if (Set-RegDword -Path $RdpTcpKey -Name 'SecurityLayer' -Value $wantSec) { $changes += "Set SecurityLayer=$wantSec" }
      else { $drifts += "Failed to set SecurityLayer=$wantSec"; $hadError = $true }
    } else { $drifts += "SecurityLayer $curSec != $wantSec" }
  }
  # MinEncryptionLevel
  $mapEnc = @{ "ClientCompatible"=2; "High"=3; "FIPS"=4 }
  $wantEnc = 3
  try {
    $encKey = [string]$cat.RDP.MinEncryptionLevel
    if ($encKey -and $mapEnc.ContainsKey($encKey)) { $wantEnc = [int]$mapEnc[$encKey] }
  } catch { $wantEnc = 3 }
  $curEnc = Get-RegDword -Path $RdpTcpKey -Name 'MinEncryptionLevel'
  if ($curEnc -ne $wantEnc) {
    if ($Remediate -and $PSCmdlet.ShouldProcess($RdpTcpKey, "Set MinEncryptionLevel=$wantEnc")) {
      if (Set-RegDword -Path $RdpTcpKey -Name 'MinEncryptionLevel' -Value $wantEnc) { $changes += "Set MinEncryptionLevel=$wantEnc" }
      else { $drifts += "Failed to set MinEncryptionLevel=$wantEnc"; $hadError = $true }
    } else { $drifts += "MinEncryptionLevel $curEnc != $wantEnc" }
  }
  # Restricted Admin (server-side): DisableRestrictedAdmin=0 enables
  $wantRA = 1; if ([bool]$cat.RDP.RestrictedAdmin) { $wantRA = 0 }
  $curRA = Get-RegDword -Path $LsaKey -Name 'DisableRestrictedAdmin'
  if ($null -eq $curRA) { $curRA = 0 }
  if ($curRA -ne $wantRA) {
    if ($Remediate -and $PSCmdlet.ShouldProcess($LsaKey, "Set DisableRestrictedAdmin=$wantRA")) {
      if (Set-RegDword -Path $LsaKey -Name 'DisableRestrictedAdmin' -Value $wantRA) { $changes += "Set DisableRestrictedAdmin=$wantRA" }
      else { $drifts += "Failed to set DisableRestrictedAdmin=$wantRA"; $hadError = $true }
    } else { $drifts += "DisableRestrictedAdmin $curRA != $wantRA" }
  }
  # PortNumber
  $wantPort = 3389
  try { if ($cat.RDP.Port) { $wantPort = [int]$cat.RDP.Port } } catch { $wantPort = 3389 }
  $curPort = Get-RegDword -Path $RdpTcpKey -Name 'PortNumber'
  if ($null -ne $curPort -and $curPort -ne $wantPort) {
    if ($Remediate -and $PSCmdlet.ShouldProcess($RdpTcpKey, "Set PortNumber=$wantPort")) {
      if (Set-RegDword -Path $RdpTcpKey -Name 'PortNumber' -Value $wantPort) { $changes += "Set PortNumber=$wantPort" }
      else { $drifts += "Failed to set PortNumber=$wantPort"; $hadError = $true }
    } else { $drifts += "PortNumber $curPort != $wantPort" }
  }
  # DisablePasswordSaving (Policies hive)
  if ($null -ne $cat.RDP.DisablePasswordSaving) {
    $wantPS = 0; if ([bool]$cat.RDP.DisablePasswordSaving) { $wantPS = 1 }
    $curPS = Get-RegDword -Path $PolTSKey -Name 'DisablePasswordSaving'
    if ($curPS -ne $wantPS) {
      $notes += "DisablePasswordSaving is under Policies hive and may be overridden by policy."
      if ($Remediate -and $PSCmdlet.ShouldProcess($PolTSKey, "Set DisablePasswordSaving=$wantPS")) {
        if (Set-RegDword -Path $PolTSKey -Name 'DisablePasswordSaving' -Value $wantPS) { $changes += "Set DisablePasswordSaving=$wantPS" }
        else { $drifts += "Failed to set DisablePasswordSaving=$wantPS"; $hadError = $true }
      } else { $drifts += "DisablePasswordSaving $curPS != $wantPS" }
    }
  }
  # Firewall
  $fw = Ensure-RdpFirewallRules -Rdp $cat.RDP -Remediate:$Remediate
  foreach ($x in @($fw)) { if ($x -match '^(Failed|Missing|.*drift|.*not |NetSecurity)') { $drifts += $x } else { $changes += $x } }
  # Group membership
  $gm = Ensure-RdpGroupMembership -Rdp $cat.RDP -Remediate:$Remediate
  foreach ($x in @($gm)) { if ($x -match '^(Failed|Missing|Unexpected|Cannot|LocalAccounts)') { $drifts += $x } else { $changes += $x } }
  # Remote Assistance
  $ra = Ensure-RemoteAssistance -Ra $cat.RemoteAssistance -Remediate:$Remediate
  foreach ($x in @($ra)) { if ($x -match '^(Failed|RemoteAssistance)') { $drifts += $x } else { $changes += $x } }
  # Result object (pipeline)
  Ensure-DirectoryForFile -FilePath $ProofPath | Out-Null
  $resultObject = [pscustomobject]@{
    TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    ComputerName = $env:COMPUTERNAME
    User         = $env:USERNAME
    Elevated     = $isElevated
    Remediate    = [bool]$Remediate
    Strict       = [bool]$Strict
    CatalogPath  = $(if ($CatalogPath) { '[configured path]' } else { $null })
    ConfigPath   = $(if ($ConfigPath) { '[configured path]' } else { $null })
    ProofPath    = $ProofPath
    Changed      = @($changes)
    Drift        = @($drifts)
    Notes        = @($notes)
    EventId      = $null
    HasError     = $hadError
    HasDrift     = (@($drifts).Count -gt 0)
  }
  # Proof JSON
  try {
    $resultObject | ConvertTo-Json -Depth 6 | Set-Content -Path $ProofPath -Encoding UTF8 -ErrorAction Stop
  } catch {
    $notes += "Failed to write proof JSON - $($_.Exception.Message)"
    $hadError = $true
    $resultObject.HasError = $true
    $resultObject.Notes = @($notes)
  }
  # Event + console message
  $duration   = (New-TimeSpan -Start $start -End (Get-Date))
  $eventIsBad = $hadError -or ($Strict -and $resultObject.HasDrift)
  $lines = @()
  if (@($changes).Count -gt 0) { $lines += "Changed: " + (@($changes) -join ' | ') }
  if (@($drifts).Count  -gt 0) { $lines += "Drift: "   + (@($drifts)  -join ' | ') }
  if (@($notes).Count   -gt 0) { $lines += "Notes: "   + (@($notes)   -join ' | ') }
  if (@($lines).Count -eq 0)   { $lines += "Compliant. No drift." }
  $lines += ("Duration: {0:00}:{1:00}:{2:00}" -f $duration.Hours, $duration.Minutes, $duration.Seconds)
  $lines += ("Proof: {0}" -f $ProofPath)
  $msg = $lines -join "`r`n"
  $resultObject.EventId = $(if ($eventIsBad) { 4850 } else { 4840 })
  if ($eventIsBad) { Write-HealthEvent -Id 4850 -Message $msg -Level 'Warning' -Source $ScriptEventSource }
  else { Write-HealthEvent -Id 4840 -Message $msg -Level 'Information' -Source $ScriptEventSource }
  # Formatted console output (no pipeline output)
  Write-UiLine ""
  Write-UiSeparator -Title "Secure Remote Access Guardrails"
  Write-KeyValue -Key "Computer"  -Value $env:COMPUTERNAME -Color Gray
  Write-KeyValue -Key "Elevated"  -Value ($isElevated.ToString()) -Color $(if ($isElevated) { 'Green' } else { 'Yellow' })
  Write-KeyValue -Key "Remediate" -Value ([bool]$Remediate) -Color $(if ($Remediate) { 'Yellow' } else { 'Gray' })
  Write-KeyValue -Key "Strict"    -Value ([bool]$Strict) -Color $(if ($Strict) { 'Yellow' } else { 'Gray' })
  Write-KeyValue -Key "EventId"   -Value $resultObject.EventId -Color $(if ($eventIsBad) { 'Yellow' } else { 'Green' })
  Write-KeyValue -Key "Proof"     -Value $ProofPath -Color Cyan
  Write-KeyValue -Key "Duration"  -Value ("{0:00}:{1:00}:{2:00}" -f $duration.Hours, $duration.Minutes, $duration.Seconds) -Color Gray
  Write-UiSeparator
  $statusColor = 'Green'
  $statusText  = 'COMPLIANT'
  if ($eventIsBad) { $statusColor = 'Yellow'; $statusText = 'ATTENTION' }
  if ($hadError) { $statusColor = 'Red'; $statusText = 'ERROR' }
  Write-UiLine -Text ("Status: {0}" -f $statusText) -Color $statusColor
  Write-KeyValue -Key "Changes" -Value (@($changes).Count) -Color $(if (@($changes).Count -gt 0) { 'Yellow' } else { 'Gray' })
  Write-KeyValue -Key "Drifts"  -Value (@($drifts).Count) -Color $(if (@($drifts).Count -gt 0) { 'Yellow' } else { 'Green' })
  Write-KeyValue -Key "Notes"   -Value (@($notes).Count) -Color $(if (@($notes).Count -gt 0) { 'Cyan' } else { 'Gray' })
  Write-UiLine ""
  Write-UiList -Header "Changes" -Items @($changes) -Color Yellow
  Write-UiList -Header "Drift"   -Items @($drifts)  -Color Yellow
  Write-UiList -Header "Notes"   -Items @($notes)   -Color Cyan
  # Optional info stream (shown only when InformationAction allows it)
  Write-Information -MessageData ("Guardrails done. EventId={0}, Proof={1}" -f $resultObject.EventId, $ProofPath) -InformationAction Continue
  # Pipeline output (single object)
  $resultObject
}
catch {
  $err = $_.Exception.Message
  Write-HealthEvent -Id 4850 -Message ("Guardrail error - " + $err) -Level 'Error' -Source $ScriptEventSource
  Ensure-DirectoryForFile -FilePath $ProofPath | Out-Null
  try {
    [pscustomobject]@{
      TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
      ComputerName = $env:COMPUTERNAME
      Error        = $err
    } | ConvertTo-Json -Depth 4 | Set-Content -Path $ProofPath -Encoding UTF8 -ErrorAction Stop
  } catch {
    Write-Warning "Could not write proof file: $($_.Exception.Message)"
  }
  Write-UiLine ""
  Write-UiSeparator -Title "Secure Remote Access Guardrails"
  Write-UiLine -Text "Status: ERROR" -Color Red
  Write-UiLine -Text ("Message: {0}" -f $err) -Color Red
  Write-UiLine -Text ("Proof:   {0}" -f $ProofPath) -Color Cyan
  Write-UiSeparator
  [pscustomobject]@{
    TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    ComputerName = $env:COMPUTERNAME
    User         = $env:USERNAME
    Elevated     = $isElevated
    Remediate    = [bool]$Remediate
    Strict       = [bool]$Strict
    CatalogPath  = $(if ($CatalogPath) { '[configured path]' } else { $null })
    ConfigPath   = $(if ($ConfigPath) { '[configured path]' } else { $null })
    ProofPath    = $ProofPath
    Changed      = @()
    Drift        = @()
    Notes        = @("Guardrail error - $err")
    EventId      = 4850
    HasError     = $true
    HasDrift     = $false
  }
}
foreach ($d in @($drifts)) {
  $code = 'RDP-Drift'
  $sev = 'Medium'
  if ($d -match 'fDenyTSConnections|UserAuthentication|NLA')            { $code = 'RDP-ConfigDrift' }
  if ($d -match 'SecurityLayer|MinEncryption')                          { $code = 'RDP-EncryptionDrift' }
  if ($d -match 'DisableRestrictedAdmin|DisablePasswordSaving')         { $code = 'RDP-SecurityDrift' }
  if ($d -match 'PortNumber')                                           { $code = 'RDP-PortDrift' }
  if ($d -match 'Failed|Missing|Unexpected')                            { $sev = 'High' }
  if ($d -match 'RemoteAssistance')                                     { $code = 'RDP-RemoteAssistDrift' }
  if ($d -match 'rule|firewall' -or $d -match 'TCP|UDP')               { $code = 'RDP-FirewallDrift' }
  if ($d -match 'member')                                               { $code = 'RDP-GroupDrift' }
  Add-Finding -FindingList $script:Findings -Code $code -Severity $sev -Message $d
}
# V2 output contract
$resultToken = if ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '14-SecureRemoteAccessGuardrails.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary ([pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Timestamp = Get-Date }) -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
