<#
.SYNOPSIS
  Audits and optionally remediates a Windows Firewall baseline (profiles, logging, and selected local firewall rules) using a JSON catalog or built-in defaults.

.DESCRIPTION
  This script evaluates a baseline in three areas:
  1) Firewall profiles (Domain/Private/Public): enabled state, default inbound/outbound actions, notifications, and logging settings.
  2) Risky inbound local rules: finds inbound rules in a chosen local policy store and flags/disables rules whose DisplayName matches configured wildcard patterns.
  3) Baseline ensure-rules: verifies required rules exist in the chosen local policy store and match key properties (direction/action/enabled/profile/port filters). Missing or drifting rules can be created/updated.

  The script supports two modes:
  - Audit (default): detects drift and reports findings.
  - Remediate (-Remediate): applies changes to match the baseline, using ShouldProcess (supports -WhatIf / -Confirm).

  Output design:
  - Pipeline output: emits structured result objects only (CSV/JSON-friendly).
  - Console output: prints a human-friendly summary and colorized findings (optional).

  Catalog loading order:
  - If -CatalogPath is provided and valid, it is used.
  - Otherwise, if -ConfigPath is provided and contains Firewall.CatalogPath, that catalog is used.
  - Otherwise, built-in defaults are used.

.PARAMETER CatalogPath
  Path to a baseline catalog JSON file.
  If provided, this takes precedence over -ConfigPath.

.PARAMETER Remediate
  If set, the script attempts to apply the baseline (update profiles, disable targeted inbound rules, and create/update ensure-rules).
  Use -WhatIf to preview changes without applying them.

.PARAMETER Strict
  If set, drift is treated as non-compliant.
  If not set, drift is reported but the compliance result is less strict (see Notes on event IDs).

.PARAMETER ConfigPath
  Path to a configuration JSON file that may contain:
    { "Firewall": { "CatalogPath": "PATH/TO/JSON" } }
  Used only when -CatalogPath is not provided or cannot be loaded.

.PARAMETER LocalPolicyStore
  The local firewall policy store to read/modify.
  Typical use is the default local persistent store; other stores can be targeted as needed.

.PARAMETER EventSource
  Event source name used when writing the health event to the Windows Event Log.

.PARAMETER EventLogName
  Event log name (for example "Application") where the health event is written.

.PARAMETER ConsoleSummary
  If set (default), prints a readable summary and colorized findings to the console host.
  If not set, no console summary is printed (pipeline output still occurs).

.PARAMETER ShowOkInConsole
  If set, the console summary also includes a list of OK items.
  By default, the console focuses on Changed/Drift/Error/Note.

.INPUTS
  None. You can't pipe input objects to this script.

.OUTPUTS
  PSCustomObject with the following properties:
    - Time:       ISO-like timestamp (local time) when the item was produced.
    - Category:   Profile | InboundRuleDisable | EnsureRule | Catalog | Runtime
    - Target:     Logical target (e.g., profile name, pattern, or rule identifier).
    - Status:     OK | Drift | Changed | Error | Note
    - Message:    Short human-readable message describing the outcome.
    - Detail:     Optional additional detail (e.g., which properties drifted).
    - Name:       Optional firewall rule Name (internal identifier).
    - DisplayName:Optional firewall rule DisplayName (user-facing title).

.NOTES
  Safety and change control:
  - Remediation is guarded by ShouldProcess; use -WhatIf for a dry run and -Confirm for interactive approval.

  Scope:
  - This script targets a selected local policy store only. It is not intended to modify centrally managed policies.

  Health event semantics:
  - Writes an event indicating overall status:
    - 4800 indicates no errors and (when not strict) drift does not force a warning state.
    - 4810 indicates drift and/or errors (and in strict mode, any drift is considered non-compliant).

  Exit codes:
  - The script does not set a custom process exit code; rely on pipeline output and the event log result.

.EXAMPLE
  # Audit using built-in defaults (no changes)
  .\18-Firewall-Baseline.ps1

.EXAMPLE
  # Audit using an explicit catalog JSON
  .\18-Firewall-Baseline.ps1 -CatalogPath "PATH/TO/BASELINE.json"

.EXAMPLE
  # Remediate using a catalog, preview only (no changes applied)
  .\18-Firewall-Baseline.ps1 -CatalogPath "PATH/TO/BASELINE.json" -Remediate -WhatIf

.EXAMPLE
  # Remediate using config-driven catalog path, suppress console summary, export results to CSV
  .\18-Firewall-Baseline.ps1 -ConfigPath "PATH/TO/CONFIG.json" -Remediate -ConsoleSummary:$false |
    Export-Csv -NoTypeInformation -Path "PATH/TO/report.csv"

.EXAMPLE
  # Audit, then filter only drift/error items for automation
  .\18-Firewall-Baseline.ps1 |
    Where-Object { $_.Status -in @('Drift','Error') } |
    ConvertTo-Json -Depth 5
#>


[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
  [string]$CatalogPath,
  [switch]$Remediate,
  [switch]$Strict,

  [string]$ConfigPath = "PATH/TO/CONFIG.json",

  [ValidateSet('PersistentStore','LocalHost','StaticServiceStore','ConfigurableServiceStore')]
  [string]$LocalPolicyStore = 'PersistentStore',

  [string]$EventSource = 'Win-Firewall-Baseline',
  [string]$EventLogName = 'Application',

  # Pretty console output. (Pipeline output is always structured objects only.)
  [switch]$ConsoleSummary = $true,

  # Show verbose "OK" items in the console summary.
  [switch]$ShowOkInConsole = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -------------------------
# Event log helpers
# -------------------------

function Ensure-EventSource {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$LogName
  )
  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
      New-EventLog -LogName $LogName -Source $Source -ErrorAction SilentlyContinue
    }
  } catch { }
}

function Write-HealthEvent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][int]$Id,
    [Parameter(Mandatory)][string]$Message,
    [ValidateSet('Information','Warning','Error')][string]$Level = 'Information',
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$LogName
  )
  try {
    Write-EventLog -LogName $LogName -Source $Source -EntryType $Level -EventId $Id -Message $Message
  } catch {
    Write-Information ("[$Level][$Id] $Message") -InformationAction Continue
  }
}

# -------------------------
# Console UI helpers (no pipeline output)
# -------------------------

function Write-UiLine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Text,
    [ConsoleColor]$Color = [ConsoleColor]::Gray
  )
  Write-Host $Text -ForegroundColor $Color
}

function Write-UiHeader {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Text)
  Write-Host ""
  Write-Host $Text -ForegroundColor Cyan
  Write-Host ("-" * $Text.Length) -ForegroundColor DarkCyan
}

function Get-StatusColor {
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateSet('OK','Drift','Changed','Error','Note')][string]$Status)

  switch ($Status) {
    'OK'      { [ConsoleColor]::Green; break }
    'Changed' { [ConsoleColor]::Cyan; break }
    'Note'    { [ConsoleColor]::DarkGray; break }
    'Drift'   { [ConsoleColor]::Yellow; break }
    'Error'   { [ConsoleColor]::Red; break }
  }
}

function Write-UiItem {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Item
  )

  $color = Get-StatusColor -Status $Item.Status
  $left  = ("[{0}] {1}/{2}" -f $Item.Status, $Item.Category, $Item.Target)
  $msg   = $Item.Message
  if (-not [string]::IsNullOrWhiteSpace($Item.DisplayName)) { $msg += " | " + $Item.DisplayName }
  if (-not [string]::IsNullOrWhiteSpace($Item.Detail))      { $msg += " | " + $Item.Detail }

  Write-Host ("- " + $left + ": " + $msg) -ForegroundColor $color
}

# -------------------------
# Generic helpers
# -------------------------

function Test-IsAdmin {
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

function Expand-EnvPath {
  [CmdletBinding()]
  param([AllowNull()][string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
  [Environment]::ExpandEnvironmentVariables($Path)
}

function Normalize-ProfileValue {
  [CmdletBinding()]
  param([AllowNull()]$Profile)
  if ($null -eq $Profile) { return @() }
  $parts = @($Profile.ToString().Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  @($parts | Sort-Object -Unique)
}

function Normalize-EnabledValue {
  [CmdletBinding()]
  param($Value)
  # NetSecurity expects "True"/"False" for -Enabled on rules.
  if ($Value -is [bool]) { return ($(if ($Value) { 'True' } else { 'False' })) }
  $s = [string]$Value
  if ($s -match '^(True|False)$') { return $s }
  if ($s -match '^(1|Enabled)$')  { return 'True' }
  if ($s -match '^(0|Disabled)$') { return 'False' }
  'True'
}

function Get-ObjProp {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Object,
    [Parameter(Mandatory)][string]$Name,
    $Default = $null
  )

  if ($null -eq $Object) { return $Default }

  if ($Object -is [System.Collections.IDictionary]) {
    if ($Object.Contains($Name)) { return $Object[$Name] }
    return $Default
  }

  $p = $Object.PSObject.Properties[$Name]
  if ($p) { return $p.Value }
  $Default
}

function Try-ReadJsonFile {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  try {
    $raw = Get-Content -Raw -LiteralPath $Path
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $raw | ConvertFrom-Json
  } catch {
    $null
  }
}

function New-ResultItem {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('Profile','InboundRuleDisable','EnsureRule','Catalog','Runtime')][string]$Category,
    [Parameter(Mandatory)][string]$Target,
    [Parameter(Mandatory)][ValidateSet('OK','Drift','Changed','Error','Note')][string]$Status,
    [string]$Message,
    [string]$Detail,
    [string]$Name,
    [string]$DisplayName
  )

  # Structured object for pipelines (CSV/JSON/etc.)
  [pscustomobject]@{
    Time        = (Get-Date).ToString('s')
    Category    = $Category
    Target      = $Target
    Status      = $Status
    Message     = $Message
    Detail      = $Detail
    Name        = $Name
    DisplayName = $DisplayName
  }
}

# -------------------------
# Default catalog (built-in)
# -------------------------

$DefaultCatalog = ConvertFrom-Json @"
{
  "Profiles": {
    "Domain":  { "Enabled": true, "DefaultInbound": "Block", "DefaultOutbound": "Allow", "NotifyOnListen": false, "LogDropped": true, "LogAllowed": false, "LogMaxSizeKB": 16384, "LogFile": "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall_domain.log" },
    "Private": { "Enabled": true, "DefaultInbound": "Block", "DefaultOutbound": "Allow", "NotifyOnListen": false, "LogDropped": true, "LogAllowed": false, "LogMaxSizeKB": 16384, "LogFile": "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall_private.log" },
    "Public":  { "Enabled": true, "DefaultInbound": "Block", "DefaultOutbound": "Allow", "NotifyOnListen": false, "LogDropped": true, "LogAllowed": false, "LogMaxSizeKB": 16384, "LogFile": "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall_public.log" }
  },
  "DisableInboundByNameLike": [
    "Remote Desktop*",
    "Remote Assistance*",
    "File and Printer Sharing*",
    "Windows Remote Management*",
    "PowerShell Remoting*"
  ],
  "EnsureRules": [
    {
      "Name": "Baseline-Outbound-Block-SMB-445-PrivPub",
      "DisplayName": "Baseline Outbound Block SMB (Private+Public)",
      "Group": "Baseline",
      "Direction": "Outbound",
      "Action": "Block",
      "Protocol": "TCP",
      "RemotePort": "445",
      "Profile": [ "Private", "Public" ],
      "Enabled": true,
      "Description": "Blocks outbound SMB to reduce lateral movement on non-domain profiles"
    },
    {
      "Name": "Baseline-Outbound-Block-LegacySMB-137-139-PrivPub",
      "DisplayName": "Baseline Outbound Block Legacy SMB (137-139) (Private+Public)",
      "Group": "Baseline",
      "Direction": "Outbound",
      "Action": "Block",
      "Protocol": "TCP",
      "RemotePort": "137-139",
      "Profile": [ "Private", "Public" ],
      "Enabled": true
    }
  ]
}
"@

function Get-EffectiveCatalog {
  [CmdletBinding()]
  param(
    [AllowNull()][string]$CatalogPath,
    [AllowNull()][string]$ConfigPath,
    [Parameter(Mandatory)]$DefaultCatalog
  )

  if ($CatalogPath) {
    $obj = Try-ReadJsonFile -Path $CatalogPath
    if ($obj) { return $obj }
  }

  if ($ConfigPath) {
    $cfg = Try-ReadJsonFile -Path $ConfigPath
    if ($cfg) {
      $fw = Get-ObjProp -Object $cfg -Name 'Firewall' -Default $null
      $cp = if ($fw) { [string](Get-ObjProp -Object $fw -Name 'CatalogPath' -Default '') } else { '' }
      if (-not [string]::IsNullOrWhiteSpace($cp)) {
        $obj = Try-ReadJsonFile -Path $cp
        if ($obj) { return $obj }
      }
    }
  }

  $DefaultCatalog
}

function Ensure-CatalogDefaults {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Catalog,
    [Parameter(Mandatory)]$DefaultCatalog
  )

  $profiles = Get-ObjProp -Object $Catalog -Name 'Profiles' -Default $null
  if (-not $profiles) {
    $Catalog | Add-Member -NotePropertyName Profiles -NotePropertyValue $DefaultCatalog.Profiles -Force
    $profiles = $Catalog.Profiles
  }

  foreach ($n in @('Domain','Private','Public')) {
    if (-not (Get-ObjProp -Object $profiles -Name $n -Default $null)) {
      $profiles | Add-Member -NotePropertyName $n -NotePropertyValue (Get-ObjProp -Object $DefaultCatalog.Profiles -Name $n) -Force
    }
  }

  if ($null -eq (Get-ObjProp -Object $Catalog -Name 'DisableInboundByNameLike' -Default $null)) {
    $Catalog | Add-Member -NotePropertyName DisableInboundByNameLike -NotePropertyValue @() -Force
  }

  if ($null -eq (Get-ObjProp -Object $Catalog -Name 'EnsureRules' -Default $null)) {
    $Catalog | Add-Member -NotePropertyName EnsureRules -NotePropertyValue @() -Force
  }

  $Catalog
}

# -------------------------
# Profile enforcement
# -------------------------

function Get-ProfileProp {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$ProfileObject,
    [Parameter(Mandatory)][string]$PropName,
    $Default = $null
  )
  $p = $ProfileObject.PSObject.Properties[$PropName]
  if ($p) { return $p.Value }
  $Default
}

function Ensure-Profile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('Domain','Private','Public')][string]$Name,
    [Parameter(Mandatory)]$Def,
    [switch]$Remediate
  )

  $out = @()

  try {
    $p = Get-NetFirewallProfile -Name $Name

    $wantEnabled  = [bool](Get-ObjProp -Object $Def -Name 'Enabled' -Default $true)
    $wantIn       = [string](Get-ObjProp -Object $Def -Name 'DefaultInbound' -Default 'Block')
    $wantOut      = [string](Get-ObjProp -Object $Def -Name 'DefaultOutbound' -Default 'Allow')
    $wantNotify   = [bool](Get-ObjProp -Object $Def -Name 'NotifyOnListen' -Default $false)

    # Catalog uses LogDropped; Set-NetFirewallProfile uses LogBlocked.
    $wantLogBlocked = Get-ObjProp -Object $Def -Name 'LogDropped' -Default $null
    $wantLogAllowed = Get-ObjProp -Object $Def -Name 'LogAllowed' -Default $null
    $wantLogKB      = Get-ObjProp -Object $Def -Name 'LogMaxSizeKB' -Default $null
    $wantLogFile    = Expand-EnvPath ([string](Get-ObjProp -Object $Def -Name 'LogFile' -Default ''))

    $haveEnabled = Get-ProfileProp -ProfileObject $p -PropName 'Enabled' -Default $null
    $haveIn      = Get-ProfileProp -ProfileObject $p -PropName 'DefaultInboundAction' -Default $null
    $haveOut     = Get-ProfileProp -ProfileObject $p -PropName 'DefaultOutboundAction' -Default $null
    $haveNotify  = Get-ProfileProp -ProfileObject $p -PropName 'NotifyOnListen' -Default $null

    $haveLogBlocked = Get-ProfileProp -ProfileObject $p -PropName 'LogBlocked' -Default $null
    $haveLogAllowed = Get-ProfileProp -ProfileObject $p -PropName 'LogAllowed' -Default $null
    $haveLogKB      = Get-ProfileProp -ProfileObject $p -PropName 'LogMaxSizeKilobytes' -Default $null
    $haveLogFile    = Expand-EnvPath ([string](Get-ProfileProp -ProfileObject $p -PropName 'LogFileName' -Default ''))

    $drift = @()
    if ($null -ne $haveEnabled -and $haveEnabled -ne $wantEnabled) { $drift += "Enabled=$haveEnabled != $wantEnabled" }
    if ($null -ne $haveIn -and $haveIn -ne $wantIn)               { $drift += "DefaultInbound=$haveIn != $wantIn" }
    if ($null -ne $haveOut -and $haveOut -ne $wantOut)            { $drift += "DefaultOutbound=$haveOut != $wantOut" }
    if ($null -ne $haveNotify -and $haveNotify -ne $wantNotify)   { $drift += "NotifyOnListen=$haveNotify != $wantNotify" }

    if ($null -ne $wantLogBlocked -and $null -ne $haveLogBlocked -and $haveLogBlocked -ne [bool]$wantLogBlocked) {
      $drift += "LogBlocked=$haveLogBlocked != $wantLogBlocked"
    }
    if ($null -ne $wantLogAllowed -and $null -ne $haveLogAllowed -and $haveLogAllowed -ne [bool]$wantLogAllowed) {
      $drift += "LogAllowed=$haveLogAllowed != $wantLogAllowed"
    }
    if ($null -ne $wantLogKB -and $null -ne $haveLogKB -and $haveLogKB -ne [int]$wantLogKB) {
      $drift += "LogMaxSizeKB=$haveLogKB != $wantLogKB"
    }
    if (-not [string]::IsNullOrWhiteSpace($wantLogFile) -and -not [string]::IsNullOrWhiteSpace($haveLogFile) -and $haveLogFile -ne $wantLogFile) {
      $drift += "LogFileName=$haveLogFile != $wantLogFile"
    }

    if ($drift.Count -eq 0) {
      $out += (New-ResultItem -Category Profile -Target $Name -Status OK -Message "Profile matches baseline")
      return $out
    }

    $out += (New-ResultItem -Category Profile -Target $Name -Status Drift -Message "Profile drift detected" -Detail ($drift -join '; '))

    if ($Remediate) {
      $spTarget = "FirewallProfile/$Name"
      if ($PSCmdlet.ShouldProcess($spTarget, "Set-NetFirewallProfile")) {
        try {
          $setParams = @{
            Name                  = $Name
            Enabled               = $wantEnabled
            DefaultInboundAction  = $wantIn
            DefaultOutboundAction = $wantOut
            NotifyOnListen        = $wantNotify
          }

          if ($null -ne $haveLogBlocked -and $null -ne $wantLogBlocked) { $setParams['LogBlocked'] = [bool]$wantLogBlocked }
          if ($null -ne $haveLogAllowed -and $null -ne $wantLogAllowed) { $setParams['LogAllowed'] = [bool]$wantLogAllowed }
          if ($null -ne $haveLogKB -and $null -ne $wantLogKB)           { $setParams['LogMaxSizeKilobytes'] = [int]$wantLogKB }
          if ($null -ne $haveLogFile -and -not [string]::IsNullOrWhiteSpace($wantLogFile)) { $setParams['LogFileName'] = $wantLogFile }

          Set-NetFirewallProfile @setParams | Out-Null
          $out += (New-ResultItem -Category Profile -Target $Name -Status Changed -Message "Profile remediated")
        } catch {
          $out += (New-ResultItem -Category Profile -Target $Name -Status Error -Message "Profile remediation failed" -Detail $_.Exception.Message)
        }
      } else {
        $out += (New-ResultItem -Category Profile -Target $Name -Status Note -Message "Remediation skipped by ShouldProcess")
      }
    }

  } catch {
    $out += (New-ResultItem -Category Profile -Target $Name -Status Error -Message "Profile query failed" -Detail $_.Exception.Message)
  }

  $out
}

# -------------------------
# Inbound rule disabling by pattern
# -------------------------

function Disable-InboundByNameLike {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string[]]$Patterns,
    [switch]$Remediate,
    [Parameter(Mandatory)][string]$LocalPolicyStore
  )

  $out = @()

  $allInbound = @()
  try {
    $allInbound = @(Get-NetFirewallRule -PolicyStore $LocalPolicyStore -Direction Inbound -ErrorAction Stop) 
  } catch {
    $out += (New-ResultItem -Category InboundRuleDisable -Target "InboundRules" -Status Error -Message "Inbound rule enumeration failed" -Detail $_.Exception.Message)
    return $out
  }

  foreach ($pat in $Patterns) {
    if ([string]::IsNullOrWhiteSpace($pat)) { continue }

    $matches = @($allInbound | Where-Object { $_.DisplayName -like $pat })
    foreach ($r in $matches) {
      if ($r.Enabled -eq 'True') {
        $out += (New-ResultItem -Category InboundRuleDisable -Target $pat -Status Drift -Message "Inbound rule enabled" -Name $r.Name -DisplayName $r.DisplayName)

        if ($Remediate) {
          $spTarget = "FirewallRule/$($r.Name)"
          if ($PSCmdlet.ShouldProcess($spTarget, "Disable inbound rule")) {
            try {
              Set-NetFirewallRule -PolicyStore $LocalPolicyStore -Name $r.Name -Enabled False | Out-Null
              $out += (New-ResultItem -Category InboundRuleDisable -Target $pat -Status Changed -Message "Inbound rule disabled" -Name $r.Name -DisplayName $r.DisplayName)
            } catch {
              $out += (New-ResultItem -Category InboundRuleDisable -Target $pat -Status Error -Message "Disable failed" -Detail $_.Exception.Message -Name $r.Name -DisplayName $r.DisplayName)
            }
          } else {
            $out += (New-ResultItem -Category InboundRuleDisable -Target $pat -Status Note -Message "Remediation skipped by ShouldProcess" -Name $r.Name -DisplayName $r.DisplayName)
          }
        }
      }
    }
  }

  if ($out.Count -eq 0) {
    $out += (New-ResultItem -Category InboundRuleDisable -Target "InboundRules" -Status OK -Message "No matching enabled inbound rules found")
  }

  $out
}

# -------------------------
# Ensure baseline rules
# -------------------------

function Ensure-FwRule {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Spec,
    [switch]$Remediate,
    [Parameter(Mandatory)][string]$LocalPolicyStore
  )

  $out = @()

  $name  = [string](Get-ObjProp -Object $Spec -Name 'Name' -Default '')
  $disp  = [string](Get-ObjProp -Object $Spec -Name 'DisplayName' -Default '')
  $grp   = [string](Get-ObjProp -Object $Spec -Name 'Group' -Default '')
  $dir   = [string](Get-ObjProp -Object $Spec -Name 'Direction' -Default '')
  $act   = [string](Get-ObjProp -Object $Spec -Name 'Action' -Default '')
  $proto = [string](Get-ObjProp -Object $Spec -Name 'Protocol' -Default '')
  $lprt  = Get-ObjProp -Object $Spec -Name 'LocalPort' -Default $null
  $rprt  = Get-ObjProp -Object $Spec -Name 'RemotePort' -Default $null
  $prog  = Get-ObjProp -Object $Spec -Name 'Program' -Default $null
  $svc   = Get-ObjProp -Object $Spec -Name 'Service' -Default $null
  $prof  = @((Get-ObjProp -Object $Spec -Name 'Profile' -Default @()) | Where-Object { $_ })
  $ena   = Normalize-EnabledValue (Get-ObjProp -Object $Spec -Name 'Enabled' -Default $true)
  $desc  = [string](Get-ObjProp -Object $Spec -Name 'Description' -Default '')

  $targetId = if ($name) { $name } else { $disp }
  if ([string]::IsNullOrWhiteSpace($targetId)) {
    $out += (New-ResultItem -Category EnsureRule -Target "EnsureRules" -Status Error -Message "Invalid rule spec: missing Name/DisplayName")
    return $out
  }

  $existing = @()
  try {
    if ($name) {
      $existing = @(Get-NetFirewallRule -PolicyStore $LocalPolicyStore -Name $name -ErrorAction SilentlyContinue) 
    }
    if ($existing.Count -eq 0 -and $disp) {
      $existing = @(Get-NetFirewallRule -PolicyStore $LocalPolicyStore -DisplayName $disp -ErrorAction SilentlyContinue)
      if ($grp) { $existing = @($existing | Where-Object { $_.Group -eq $grp }) }
    }
  } catch {
    $out += (New-ResultItem -Category EnsureRule -Target $targetId -Status Error -Message "Rule query failed" -Detail $_.Exception.Message -Name $name -DisplayName $disp)
    return $out
  }

  if ($existing.Count -eq 0) {
    $out += (New-ResultItem -Category EnsureRule -Target $targetId -Status Drift -Message "Missing rule" -Name $name -DisplayName $disp)

    if ($Remediate) {
      $spTarget = "FirewallRule/(create)/$targetId"
      if ($PSCmdlet.ShouldProcess($spTarget, "New-NetFirewallRule")) {
        try {
          # Rules can only be added to a store at creation time.
          $params = @{
            PolicyStore = $LocalPolicyStore
            Direction   = $dir
            Action      = $act
            Protocol    = $proto
            Enabled     = $ena
          }
          if ($name) { $params['Name'] = $name }
          if ($disp) { $params['DisplayName'] = $disp }
          if ($grp)  { $params['Group'] = $grp }
          if ($lprt) { $params['LocalPort'] = $lprt }
          if ($rprt) { $params['RemotePort'] = $rprt }
          if ($prog) { $params['Program'] = $prog }
          if ($svc)  { $params['Service'] = $svc }
          if ($prof.Count -gt 0) { $params['Profile'] = $prof }
          if ($desc) { $params['Description'] = $desc }

          New-NetFirewallRule @params | Out-Null
          $out += (New-ResultItem -Category EnsureRule -Target $targetId -Status Changed -Message "Rule created" -Name $name -DisplayName $disp)
        } catch {
          $out += (New-ResultItem -Category EnsureRule -Target $targetId -Status Error -Message "Rule create failed" -Detail $_.Exception.Message -Name $name -DisplayName $disp)
        }
      } else {
        $out += (New-ResultItem -Category EnsureRule -Target $targetId -Status Note -Message "Remediation skipped by ShouldProcess" -Name $name -DisplayName $disp)
      }
    }

    return $out
  }

  foreach ($r in $existing) {
    $need = @()

    if ($dir -and $r.Direction -ne $dir) { $need += "Direction" }
    if ($act -and $r.Action -ne $act)    { $need += "Action" }
    if ($r.Enabled -ne $ena)             { $need += "Enabled" }
    if ($grp -and $r.Group -ne $grp)     { $need += "Group" }

    $haveProf = Normalize-ProfileValue $r.Profile
    $wantProf = Normalize-ProfileValue $prof
    if ($wantProf.Count -gt 0 -and ((@($haveProf) -join ',') -ne (@($wantProf) -join ','))) { $need += "Profile" }

    $pf = $null
    try { $pf = Get-NetFirewallRule -PolicyStore $LocalPolicyStore -Name $r.Name | Get-NetFirewallPortFilter } catch { }

    if ($pf) {
      if ($proto -and $pf.Protocol -ne $proto) { $need += "Protocol" }
      if ($lprt  -and $pf.LocalPort  -ne $lprt) { $need += "LocalPort" }
      if ($rprt  -and $pf.RemotePort -ne $rprt) { $need += "RemotePort" }
    }

    if ($need.Count -eq 0) {
      $out += (New-ResultItem -Category EnsureRule -Target $targetId -Status OK -Message "Rule matches baseline" -Name $r.Name -DisplayName $r.DisplayName)
      continue
    }

    $out += (New-ResultItem -Category EnsureRule -Target $targetId -Status Drift -Message "Rule drift detected" -Detail ($need -join ', ') -Name $r.Name -DisplayName $r.DisplayName)

    if ($Remediate) {
      $spTarget = "FirewallRule/$($r.Name)"
      if ($PSCmdlet.ShouldProcess($spTarget, "Set-NetFirewallRule / Set-NetFirewallPortFilter")) {
        try {
          $setParams = @{
            PolicyStore = $LocalPolicyStore
            Name        = $r.Name
            Enabled     = $ena
          }
          if ($dir) { $setParams['Direction'] = $dir }
          if ($act) { $setParams['Action']    = $act }
          if ($grp) { $setParams['Group']     = $grp }
          if ($prof.Count -gt 0) { $setParams['Profile'] = $prof }
          Set-NetFirewallRule @setParams | Out-Null

          if ($pf -and ($proto -or $lprt -or $rprt)) {
            $portParams = @{}
            if ($proto) { $portParams['Protocol']  = $proto }
            if ($lprt)  { $portParams['LocalPort'] = $lprt }
            if ($rprt)  { $portParams['RemotePort']= $rprt }
            Set-NetFirewallPortFilter -InputObject $pf @portParams | Out-Null
          }

          if ($desc) {
            Set-NetFirewallRule -PolicyStore $LocalPolicyStore -Name $r.Name -Description $desc -ErrorAction SilentlyContinue | Out-Null
          }

          $out += (New-ResultItem -Category EnsureRule -Target $targetId -Status Changed -Message "Rule remediated" -Name $r.Name -DisplayName $r.DisplayName)
        } catch {
          $out += (New-ResultItem -Category EnsureRule -Target $targetId -Status Error -Message "Rule remediation failed" -Detail $_.Exception.Message -Name $r.Name -DisplayName $r.DisplayName)
        }
      } else {
        $out += (New-ResultItem -Category EnsureRule -Target $targetId -Status Note -Message "Remediation skipped by ShouldProcess" -Name $r.Name -DisplayName $r.DisplayName)
      }
    }
  }

  $out
}

function Write-ConsoleSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][System.Collections.IEnumerable]$Results,
    [Parameter(Mandatory)][timespan]$Duration,
    [Parameter(Mandatory)][bool]$Elevated,
    [Parameter(Mandatory)][bool]$Remediate,
    [Parameter(Mandatory)][bool]$Strict,
    [Parameter(Mandatory)][string]$PolicyStore,
    [Parameter(Mandatory)][bool]$ShowOk
  )

  $items = @($Results)

  $driftCount  = @($items | Where-Object { $_.Status -eq 'Drift'   }).Count
  $errorCount  = @($items | Where-Object { $_.Status -eq 'Error'   }).Count
  $changeCount = @($items | Where-Object { $_.Status -eq 'Changed' }).Count
  $noteCount   = @($items | Where-Object { $_.Status -eq 'Note'    }).Count
  $okCount     = @($items | Where-Object { $_.Status -eq 'OK'      }).Count

  $mode = if ($Remediate) { 'Remediate' } else { 'Audit' }

  Write-UiHeader -Text "Firewall baseline summary"
  Write-UiLine -Text ("Mode:        " + $mode) -Color Gray
  Write-UiLine -Text ("Strict:      " + $Strict) -Color Gray
  Write-UiLine -Text ("Elevated:    " + $Elevated) -Color Gray
  Write-UiLine -Text ("PolicyStore: " + $PolicyStore) -Color Gray
  Write-UiLine -Text ("Duration:    " + [string]$Duration) -Color Gray
  Write-Host ""

  Write-UiLine -Text ("Changed:     " + $changeCount) -Color Cyan
  Write-UiLine -Text ("Drift:       " + $driftCount) -Color Yellow
  Write-UiLine -Text ("Errors:      " + $errorCount) -Color Red
  Write-UiLine -Text ("Notes:       " + $noteCount) -Color DarkGray
  if ($ShowOk) { Write-UiLine -Text ("OK:          " + $okCount) -Color Green }
  Write-Host ""

  # Show important items first
  $top = $items | Where-Object { $_.Status -in @('Error','Drift','Changed','Note') }
  if (-not $ShowOk) { $top = $top | Where-Object { $_.Status -ne 'OK' } }

  if (@($top).Count -gt 0) {
    Write-UiHeader -Text "Findings (top 25)"
    $top | Select-Object -First 25 | ForEach-Object { Write-UiItem -Item $_ }
  }

  if ($ShowOk -and $okCount -gt 0) {
    Write-UiHeader -Text "OK items (top 25)"
    ($items | Where-Object { $_.Status -eq 'OK' } | Select-Object -First 25) | ForEach-Object { Write-UiItem -Item $_ }
  }
}

# -------------------------
# Main
# -------------------------

Ensure-EventSource -Source $EventSource -LogName $EventLogName

$start = Get-Date
$isAdmin = Test-IsAdmin

$results = New-Object System.Collections.Generic.List[object]

if (-not $isAdmin) {
  $results.Add((New-ResultItem -Category Runtime -Target "Elevation" -Status Note -Message "Not elevated: remediation may fail"))
}

$cat = Get-EffectiveCatalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath -DefaultCatalog $DefaultCatalog
if ($null -eq $cat) {
  $cat = $DefaultCatalog
  $results.Add((New-ResultItem -Category Catalog -Target "Catalog" -Status Note -Message "Catalog not loaded; using built-in defaults"))
}
$cat = Ensure-CatalogDefaults -Catalog $cat -DefaultCatalog $DefaultCatalog

# Profiles
foreach ($n in @('Domain','Private','Public')) {
  $def = Get-ObjProp -Object $cat.Profiles -Name $n -Default $DefaultCatalog.Profiles.$n
  (Ensure-Profile -Name $n -Def $def -Remediate:$Remediate) | ForEach-Object { $results.Add($_) }
}

# Disable inbound patterns
$patterns = @((Get-ObjProp -Object $cat -Name 'DisableInboundByNameLike' -Default @()) | Where-Object { $_ -is [string] -and $_ })
(Disable-InboundByNameLike -Patterns $patterns -Remediate:$Remediate -LocalPolicyStore $LocalPolicyStore) | ForEach-Object { $results.Add($_) }

# Ensure rules
$ensureRules = @((Get-ObjProp -Object $cat -Name 'EnsureRules' -Default @()) | Where-Object { $_ })
foreach ($rule in $ensureRules) {
  (Ensure-FwRule -Spec $rule -Remediate:$Remediate -LocalPolicyStore $LocalPolicyStore) | ForEach-Object { $results.Add($_) }
}

$duration = (New-TimeSpan -Start $start -End (Get-Date))

$hasError = @($results | Where-Object { $_.Status -eq 'Error' }).Count -gt 0
$hasDrift = @($results | Where-Object { $_.Status -eq 'Drift' }).Count -gt 0

# Strict means: any drift flips to WARN (4810)
$ok = (-not $hasError) -and (-not ($Strict -and $hasDrift))

$eventId = if ($ok) { 4800 } else { 4810 }
$level   = if ($ok) { 'Information' } else { 'Warning' }

# Compact event message; no formatting.
$eventSummary = "Mode={0}; Elevated={1}; PolicyStore={2}; Changed={3}; Drift={4}; Errors={5}; Duration={6}" -f `
  ($(if ($Remediate) { 'Remediate' } else { 'Audit' })), $isAdmin, $LocalPolicyStore, `
  (@($results | Where-Object { $_.Status -eq 'Changed' }).Count), `
  (@($results | Where-Object { $_.Status -eq 'Drift' }).Count), `
  (@($results | Where-Object { $_.Status -eq 'Error' }).Count), `
  ([string]$duration)

Write-HealthEvent -Id $eventId -Message $eventSummary -Level $level -Source $EventSource -LogName $EventLogName

if ($ConsoleSummary) {
  Write-ConsoleSummary -Results $results -Duration $duration -Elevated $isAdmin -Remediate $Remediate -Strict $Strict -PolicyStore $LocalPolicyStore -ShowOk $ShowOkInConsole
}

# Pipeline output: structured objects only
$results
