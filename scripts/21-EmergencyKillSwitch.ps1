<#
.SYNOPSIS
  Immediately isolates a Windows host during an incident by enforcing a "block all" network posture using Windows Firewall,
  with optional break-glass access, optional adapter shutdown, and optional automatic rollback.

.DESCRIPTION
  This script is an emergency kill switch for incident response. It is designed to be run locally or remotely with administrative rights.

  Core actions (in order):
  1) Writes an audit/quarantine flag to the registry (timestamp + reason + optional user).
  2) Optionally schedules an automatic rollback after a specified number of minutes.
  3) Enforces Windows Firewall "block all" behavior by setting profile defaults to Block for inbound and outbound traffic.
  4) Creates explicit, idempotent firewall rules for traceability (stable rule names, safe to run multiple times).
  5) Optionally creates a break-glass inbound allow rule for specified remote IPs/subnets.
  6) Optionally disables active network adapters (very aggressive; may cut off remote access immediately).

  Output behavior:
  - The script prints a human-friendly, colored status and a final summary to the console.
  - The script emits exactly one structured object to the success pipeline, suitable for Export-Csv / ConvertTo-Json / filtering.

  Safety behavior:
  - Uses ShouldProcess / Confirm semantics. If confirmations are declined, the script records that and reports it in the summary.
  - Any failure is recorded in the structured result and in the console summary.

.PARAMETER Reason
  A human-readable reason that is written to the registry and included in the event message, for auditing and automation.

.PARAMETER DisableAdapters
  If set, disables all network adapters that are currently in "Up" state.
  This is extremely disruptive and should only be used when losing remote connectivity is acceptable.

.PARAMETER BreakGlassRemoteAddress
  One or more remote IP addresses or CIDR subnets that should be allowed inbound (break-glass).
  Use this to preserve a controlled recovery path (for example, an admin jump host subnet).
  If not provided, any existing break-glass rule created by this script is removed.

.PARAMETER AutoRollbackMinutes
  If greater than 0, schedules a one-time rollback that:
  - Restores firewall profile defaults to Allow (inbound/outbound),
  - Removes the kill-switch firewall rules created by this script,
  - Removes the rollback task after it runs.
  Use this to reduce the risk of permanent lockout when executing remotely.

.PARAMETER ConfigJsonPath
  Optional path to a JSON configuration file (example: "PATH/TO/JSON/kill-switch.json").
  If the file is missing or invalid, the script continues with safe defaults and/or explicit parameters.

.PARAMETER ConfigJsonRaw
  Optional raw JSON string. If provided, it takes precedence over ConfigJsonPath.
  If invalid, the script continues with safe defaults and/or explicit parameters.

.OUTPUTS
  System.Management.Automation.PSCustomObject

  The script writes exactly one object to the success pipeline with run metadata, effective configuration,
  action results, outcome status (IsolationActive), and an error list.

.NOTES
  Requirements:
  - Administrative privileges are required.

  Operational considerations:
  - Running with -DisableAdapters can immediately drop the current remote session.
  - Break-glass should be planned in advance (known management subnet/IPs).
  - AutoRollback is a safety net; ensure it aligns with your incident response policy.

.EXAMPLE
  PS> .\21-EmergencyKillSwitch.ps1

  Runs with built-in defaults (no break-glass, no adapter disable, no auto-rollback).
  Confirmation prompts may appear depending on your preference settings.

.EXAMPLE
  PS> .\21-EmergencyKillSwitch.ps1 -Reason "Suspected malware beaconing"

  Same as default, but records a custom reason in the audit flag and event message.

.EXAMPLE
  PS> .\21-EmergencyKillSwitch.ps1 -BreakGlassRemoteAddress "10.10.10.0/24","203.0.113.10" -AutoRollbackMinutes 30

  Activates isolation while allowing inbound break-glass from the specified subnet/IP, and schedules rollback after 30 minutes.

.EXAMPLE
  PS> .\21-EmergencyKillSwitch.ps1 -DisableAdapters -AutoRollbackMinutes 10 -Confirm:$false

  Aggressively isolates the host (including disabling adapters) and schedules rollback after 10 minutes.
  -Confirm:$false suppresses confirmation prompts.

.EXAMPLE
  PS> $r = .\21-EmergencyKillSwitch.ps1 -ConfigJsonPath "PATH/TO/JSON/kill-switch.json" -Confirm:$false
  PS> $r | ConvertTo-Json -Depth 6
  PS> $r.Errors | Out-String

  Runs using optional JSON configuration, captures the structured result object, and exports it for logging/automation.

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$Reason = "Incident/Compromise/Manual KillSwitch",
  [switch]$DisableAdapters,
  [string[]]$BreakGlassRemoteAddress = @(),
  [ValidateRange(0, 1440)]
  [int]$AutoRollbackMinutes = 0,

  [string]$ConfigJsonPath = "PATH/TO/JSON/kill-switch.json",
  [string]$ConfigJsonRaw
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# -------------------- Safe defaults
$Defaults = [ordered]@{
  EventSource = 'KillSwitch'
  EventLog    = 'Application'
  EventId     = 9001

  RegKey      = 'HKLM:\SOFTWARE\KillSwitch\Quarantine'

  RulePrefix  = 'KILLSWITCH'
  TaskName    = 'KILLSWITCH-ROLLBACK'

  IncludeUserInRegistry = $true

  DisableAdapters         = $false
  BreakGlassRemoteAddress = @()
  AutoRollbackMinutes     = 0
}

# -------------------- Run state for summary + pipeline output
$Run = [ordered]@{
  StartTime    = Get-Date
  EndTime      = $null
  Duration     = $null

  ComputerName = $env:COMPUTERNAME
  User         = "$env:USERDOMAIN\$env:USERNAME"
  IsAdmin      = $false

  JsonPath     = $ConfigJsonPath
  JsonUsed     = $false
  JsonError    = $null

  Effective    = [ordered]@{
    Reason                 = $Reason
    DisableAdapters         = $DisableAdapters.IsPresent
    BreakGlassRemoteAddress = @()
    AutoRollbackMinutes     = $AutoRollbackMinutes

    EventSource             = $Defaults.EventSource
    EventLog                = $Defaults.EventLog
    EventId                 = $Defaults.EventId

    RegKey                  = $Defaults.RegKey
    RulePrefix              = $Defaults.RulePrefix
    TaskName                = $Defaults.TaskName
    IncludeUserInRegistry   = $Defaults.IncludeUserInRegistry
  }

  Actions      = [ordered]@{
    RegistryWritten     = $false
    EventLogWritten     = $false
    FirewallProfileSet  = $false
    RulesCreated        = $false
    BreakGlassApplied   = $false
    AdaptersDisabled    = $false
    RollbackScheduled   = $false

    # Tracks if user declined confirmations
    ConfirmDeclined     = $false
  }

  Outcome      = [ordered]@{
    IsolationActive     = $false
    IsolationIntended   = $true
  }

  Errors       = New-Object System.Collections.Generic.List[string]
}

function Add-RunError {
  param([string]$Message)
  [void]$Run.Errors.Add($Message)
}

# ---------- Console helpers (never write to pipeline)
function Write-UiLine {
  param([string]$Text = '', [ConsoleColor]$Color = 'Gray')
  Write-Host $Text -ForegroundColor $Color
}

function Write-UiHeader {
  param([string]$Title)
  Write-Host ""
  Write-Host ("=" * 78) -ForegroundColor DarkGray
  Write-Host ("  {0}" -f $Title) -ForegroundColor Cyan
  Write-Host ("=" * 78) -ForegroundColor DarkGray
}

function Write-UiKV {
  param(
    [string]$Key,
    [object]$Value,
    [ConsoleColor]$KeyColor = 'DarkGray',
    [ConsoleColor]$ValueColor = 'Gray'
  )
  $v = if ($null -eq $Value) { '' } else { [string]$Value }
  Write-Host ("{0,-24}: " -f $Key) -ForegroundColor $KeyColor -NoNewline
  Write-Host $v -ForegroundColor $ValueColor
}

function Write-UiBool {
  param([string]$Key,[bool]$Value)
  $c = if ($Value) { [ConsoleColor]::Green } else { [ConsoleColor]::DarkGray }
  Write-UiKV -Key $Key -Value $Value -ValueColor $c
}

function Test-IsAdmin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Try-LoadConfigJson {
  param([string]$Path,[string]$Raw)

  try {
    if ($Raw -and $Raw.Trim()) {
      return ($Raw | ConvertFrom-Json)
    }

    if ($Path -and (Test-Path -LiteralPath $Path)) {
      $text = Get-Content -LiteralPath $Path -Raw
      if ($text -and $text.Trim()) {
        return ($text | ConvertFrom-Json)
      }
    }

    return $null
  } catch {
    $Run.JsonError = $_.Exception.Message
    return $null
  }
}

function Get-ConfigValue {
  param(
    [object]$Config,
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][object]$Default
  )

  if ($null -eq $Config) { return $Default }

  $p = $Config.PSObject.Properties[$Name]
  if ($null -eq $p) { return $Default }

  if ($p.Value -is [string] -and -not $p.Value.Trim()) { return $Default }

  return $p.Value
}

function Ensure-EventSource {
  param([string]$Source,[string]$Log)

  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
      New-EventLog -LogName $Log -Source $Source
    }
  } catch {
    Add-RunError "Event source check/create failed: $($_.Exception.Message)"
  }
}

function Write-HealthEvent {
  param(
    [string]$Log,
    [string]$Source,
    [int]$Id,
    [string]$Msg,
    [ValidateSet('Information','Warning','Error')]
    [string]$Level = 'Information'
  )

  try {
    Write-EventLog -LogName $Log -Source $Source -EntryType $Level -EventId $Id -Message $Msg
    $Run.Actions.EventLogWritten = $true
  } catch {
    Add-RunError "Event write failed: $($_.Exception.Message)"
    Write-Host "[$Level][$Id] $Msg" -ForegroundColor Yellow
  }
}

function Set-QuarantineFlag {
  param(
    [string]$RegKey,
    [string]$ReasonText,
    [bool]$IncludeUser
  )

  try {
    New-Item -Path $RegKey -Force | Out-Null
    Set-ItemProperty -Path $RegKey -Name 'Isolated' -Value 1 -Force
    Set-ItemProperty -Path $RegKey -Name 'Time'     -Value ((Get-Date).ToString('s')) -Force
    Set-ItemProperty -Path $RegKey -Name 'Reason'   -Value $ReasonText -Force
    if ($IncludeUser) {
      Set-ItemProperty -Path $RegKey -Name 'User' -Value $Run.User -Force
    }
    $Run.Actions.RegistryWritten = $true
  } catch {
    Add-RunError "Registry flag write failed: $($_.Exception.Message)"
  }
}

function New-OrReplaceRule {
  param(
    [string]$Name,
    [string]$DisplayName,
    [ValidateSet('Inbound','Outbound')]
    [string]$Direction,
    [ValidateSet('Block','Allow')]
    [string]$Action,
    [string[]]$RemoteAddress = @(),
    [string]$Description = ''
  )

  Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

  $params = @{
    Name        = $Name
    DisplayName = $DisplayName
    Direction   = $Direction
    Action      = $Action
    Profile     = 'Any'
    Enabled     = 'True'
    Description = $Description
  }

  if ($RemoteAddress -and $RemoteAddress.Count -gt 0) {
    $params.RemoteAddress = $RemoteAddress
  }

  New-NetFirewallRule @params | Out-Null
}

function Schedule-AutoRollback {
  param(
    [int]$Minutes,
    [string]$TaskName,
    [string[]]$RuleNames
  )

  if ($Minutes -le 0) { return $false }

  $runAt = (Get-Date).AddMinutes($Minutes)

  $rollbackPs = @"
`$ErrorActionPreference='SilentlyContinue';
Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow;
Get-NetFirewallRule -Name '$($RuleNames -join "','")' | Remove-NetFirewallRule;
schtasks.exe /Delete /TN '$TaskName' /F | Out-Null;
"@

  $bytes = [System.Text.Encoding]::Unicode.GetBytes($rollbackPs)
  $enc   = [Convert]::ToBase64String($bytes)
  $tr    = "PowerShell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc"

  try {
    schtasks.exe /Create /TN $TaskName /SC ONCE /ST $runAt.ToString('HH:mm') /TR $tr /RL HIGHEST /F | Out-Null
    return $true
  } catch {
    Add-RunError "Auto-rollback schedule failed: $($_.Exception.Message)"
    return $false
  }
}

function Update-Outcome {
  # Consider isolation "active" only if at least the firewall default policy was set OR rules were created.
  $Run.Outcome.IsolationActive = [bool]($Run.Actions.FirewallProfileSet -or $Run.Actions.RulesCreated -or $Run.Actions.AdaptersDisabled)
}

function Write-ConsoleSummary {
  $Run.EndTime = Get-Date
  $Run.Duration = New-TimeSpan -Start $Run.StartTime -End $Run.EndTime

  Update-Outcome

  $hasProblems = ($Run.Errors.Count -gt 0) -or ($Run.Actions.ConfirmDeclined)

  $title = 'Kill Switch Summary (OK)'
  if ($hasProblems) { $title = 'Kill Switch Summary (Attention)' }

  $durationColor = [ConsoleColor]::Green
  if ($hasProblems) { $durationColor = [ConsoleColor]::Yellow }

  $jsonUsedColor = [ConsoleColor]::DarkGray
  if ($Run.JsonUsed) { $jsonUsedColor = [ConsoleColor]::Green }

  Write-UiHeader -Title $title

  Write-UiKV   -Key 'ComputerName' -Value $Run.ComputerName -ValueColor White
  Write-UiKV   -Key 'User'         -Value $Run.User
  Write-UiBool -Key 'Admin'        -Value $Run.IsAdmin
  Write-UiKV   -Key 'StartTime'    -Value $Run.StartTime.ToString('s')
  Write-UiKV   -Key 'EndTime'      -Value $Run.EndTime.ToString('s')
  Write-UiKV   -Key 'Duration'     -Value $Run.Duration -ValueColor $durationColor

  Write-Host ""
  Write-UiKV -Key 'JSON used' -Value $Run.JsonUsed -ValueColor $jsonUsedColor
  Write-UiKV -Key 'JSON path' -Value $Run.JsonPath
  if ($Run.JsonError) { Write-UiKV -Key 'JSON error' -Value $Run.JsonError -ValueColor Yellow }

  Write-Host ""
  Write-UiKV   -Key 'Reason' -Value $Run.Effective.Reason -ValueColor Cyan
  Write-UiBool -Key 'IsolationActive' -Value $Run.Outcome.IsolationActive
  Write-UiBool -Key 'DisableAdapters' -Value ([bool]$Run.Effective.DisableAdapters)
  Write-UiKV   -Key 'BreakGlass' -Value ($Run.Effective.BreakGlassRemoteAddress -join ', ')
  Write-UiKV   -Key 'AutoRollbackMinutes' -Value $Run.Effective.AutoRollbackMinutes

  Write-Host ""
  Write-UiBool -Key 'RegistryWritten'    -Value $Run.Actions.RegistryWritten
  Write-UiBool -Key 'EventLogWritten'    -Value $Run.Actions.EventLogWritten
  Write-UiBool -Key 'FirewallProfileSet' -Value $Run.Actions.FirewallProfileSet
  Write-UiBool -Key 'RulesCreated'       -Value $Run.Actions.RulesCreated
  Write-UiBool -Key 'BreakGlassApplied'  -Value $Run.Actions.BreakGlassApplied
  Write-UiBool -Key 'AdaptersDisabled'   -Value $Run.Actions.AdaptersDisabled
  Write-UiBool -Key 'RollbackScheduled'  -Value $Run.Actions.RollbackScheduled

  if ($Run.Actions.ConfirmDeclined) {
    Write-Host ""
    Write-UiLine -Text "NOTE: One or more operations were declined in a Confirm prompt (No / No to All)." -Color Yellow
  }

  if ($Run.Errors.Count -gt 0) {
    Write-Host ""
    Write-UiLine -Text "Warnings/Errors:" -Color Yellow
    foreach ($e in $Run.Errors) { Write-UiLine -Text ("- {0}" -f $e) -Color Yellow }
  }

  Write-Host ("-" * 78) -ForegroundColor DarkGray
}


# -------------------- Load JSON (optional) and merge with defaults/parameters
$config = Try-LoadConfigJson -Path $ConfigJsonPath -Raw $ConfigJsonRaw
if ($null -ne $config) { $Run.JsonUsed = $true }

$Run.Effective.EventSource = Get-ConfigValue -Config $config -Name 'EventSource' -Default $Defaults.EventSource
$Run.Effective.EventLog    = Get-ConfigValue -Config $config -Name 'EventLog'    -Default $Defaults.EventLog
$Run.Effective.EventId     = [int](Get-ConfigValue -Config $config -Name 'EventId' -Default $Defaults.EventId)

$Run.Effective.RegKey      = Get-ConfigValue -Config $config -Name 'RegKey'     -Default $Defaults.RegKey
$Run.Effective.RulePrefix  = Get-ConfigValue -Config $config -Name 'RulePrefix' -Default $Defaults.RulePrefix
$Run.Effective.TaskName    = Get-ConfigValue -Config $config -Name 'TaskName'   -Default $Defaults.TaskName
$Run.Effective.IncludeUserInRegistry = [bool](Get-ConfigValue -Config $config -Name 'IncludeUserInRegistry' -Default $Defaults.IncludeUserInRegistry)

# Apply JSON defaults only if caller did not provide explicit values
if (-not $DisableAdapters.IsPresent) {
  $fromJson = [bool](Get-ConfigValue -Config $config -Name 'DisableAdapters' -Default $Defaults.DisableAdapters)
  if ($fromJson) { $DisableAdapters = $true }
}
if ($BreakGlassRemoteAddress.Count -eq 0) {
  $bg = Get-ConfigValue -Config $config -Name 'BreakGlassRemoteAddress' -Default $Defaults.BreakGlassRemoteAddress
  if ($bg) { $BreakGlassRemoteAddress = @($bg) }
}
if ($AutoRollbackMinutes -eq 0) {
  $arm = [int](Get-ConfigValue -Config $config -Name 'AutoRollbackMinutes' -Default $Defaults.AutoRollbackMinutes)
  if ($arm -gt 0) { $AutoRollbackMinutes = $arm }
}

$Run.Effective.Reason                 = $Reason
$Run.Effective.DisableAdapters         = $DisableAdapters.IsPresent
$Run.Effective.BreakGlassRemoteAddress = @($BreakGlassRemoteAddress)
$Run.Effective.AutoRollbackMinutes     = $AutoRollbackMinutes

# Derived identifiers
$RuleInName  = "{0}-IN-BLOCK"            -f $Run.Effective.RulePrefix
$RuleOutName = "{0}-OUT-BLOCK"           -f $Run.Effective.RulePrefix
$RuleBgName  = "{0}-BREAKGLASS-IN-ALLOW" -f $Run.Effective.RulePrefix
$RuleNames   = @($RuleInName, $RuleOutName, $RuleBgName)

# -------------------- Execution
$Run.IsAdmin = Test-IsAdmin

Ensure-EventSource -Source $Run.Effective.EventSource -Log $Run.Effective.EventLog

if (-not $Run.IsAdmin) {
  Write-UiHeader -Title "Kill Switch"
  Write-UiLine -Text "ERROR: Admin privileges required. Aborting." -Color Red

  Write-HealthEvent -Log $Run.Effective.EventLog -Source $Run.Effective.EventSource -Id $Run.Effective.EventId `
    -Msg "KillSwitch aborted: admin privileges required." -Level 'Error'

  Write-ConsoleSummary
  [pscustomobject]$Run
  return
}

try {
  Set-QuarantineFlag -RegKey $Run.Effective.RegKey -ReasonText $Run.Effective.Reason -IncludeUser $Run.Effective.IncludeUserInRegistry

  if ($Run.Effective.AutoRollbackMinutes -gt 0) {
    $Run.Actions.RollbackScheduled = Schedule-AutoRollback -Minutes $Run.Effective.AutoRollbackMinutes -TaskName $Run.Effective.TaskName -RuleNames $RuleNames
  }

  if ($PSCmdlet.ShouldProcess("Windows Firewall Profiles", "Enable firewall + set DefaultInboundAction=Block, DefaultOutboundAction=Block")) {
    Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
    $Run.Actions.FirewallProfileSet = $true
  } else {
    $Run.Actions.ConfirmDeclined = $true
  }

  if ($PSCmdlet.ShouldProcess("Windows Defender Firewall Rules", "Create kill switch rules")) {
    New-OrReplaceRule -Name $RuleInName  -DisplayName "$($Run.Effective.RulePrefix) Inbound Block"  -Direction Inbound  -Action Block -Description "Kill switch: block inbound"
    New-OrReplaceRule -Name $RuleOutName -DisplayName "$($Run.Effective.RulePrefix) Outbound Block" -Direction Outbound -Action Block -Description "Kill switch: block outbound"
    $Run.Actions.RulesCreated = $true
  } else {
    $Run.Actions.ConfirmDeclined = $true
  }

  if ($Run.Effective.BreakGlassRemoteAddress -and $Run.Effective.BreakGlassRemoteAddress.Count -gt 0) {
    if ($PSCmdlet.ShouldProcess("Windows Defender Firewall Rules", "Create break-glass inbound allow rule")) {
      New-OrReplaceRule -Name $RuleBgName -DisplayName "$($Run.Effective.RulePrefix) BreakGlass Inbound Allow" `
        -Direction Inbound -Action Allow -RemoteAddress $Run.Effective.BreakGlassRemoteAddress -Description "Kill switch: break-glass inbound allow"
      $Run.Actions.BreakGlassApplied = $true
    } else {
      $Run.Actions.ConfirmDeclined = $true
    }
  } else {
    Get-NetFirewallRule -Name $RuleBgName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  }

  if ($DisableAdapters) {
    if ($PSCmdlet.ShouldProcess("Network Adapters", "Disable all Up adapters")) {
      $netAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
      foreach ($a in $netAdapters) {
        Disable-NetAdapter -Name $a.Name -Confirm:$false
      }
      $Run.Actions.AdaptersDisabled = $true
    } else {
      $Run.Actions.ConfirmDeclined = $true
    }
  }

  Update-Outcome

  $level = if ($Run.Outcome.IsolationActive) { 'Warning' } else { 'Information' }
  $eventMsg = @"
Kill switch run completed.
IsolationActive: $($Run.Outcome.IsolationActive)
Reason: $($Run.Effective.Reason)
Time  : $(Get-Date -Format 's')
FirewallProfileSet: $($Run.Actions.FirewallProfileSet)
RulesCreated: $($Run.Actions.RulesCreated)
AdaptersDisabled: $($Run.Actions.AdaptersDisabled)
BreakGlassApplied: $($Run.Actions.BreakGlassApplied)
AutoRollbackMinutes: $($Run.Effective.AutoRollbackMinutes)
"@.Trim()

  Write-HealthEvent -Log $Run.Effective.EventLog -Source $Run.Effective.EventSource -Id $Run.Effective.EventId -Msg $eventMsg -Level $level

  Write-UiHeader -Title "Kill Switch"
  if ($Run.Outcome.IsolationActive) {
    Write-UiLine -Text "Isolation is ACTIVE." -Color Green
  } else {
    Write-UiLine -Text "Isolation is NOT active (actions were skipped/declined)." -Color Yellow
  }
  Write-UiKV -Key 'Reason' -Value $Run.Effective.Reason -ValueColor Cyan
  Write-UiKV -Key 'BreakGlass' -Value ($Run.Effective.BreakGlassRemoteAddress -join ', ')
  Write-UiKV -Key 'AutoRollbackMinutes' -Value $Run.Effective.AutoRollbackMinutes
}
catch {
  $err = $_.Exception.Message
  Add-RunError "Unhandled error: $err"

  Write-HealthEvent -Log $Run.Effective.EventLog -Source $Run.Effective.EventSource -Id $Run.Effective.EventId `
    -Msg ("KillSwitch failed: {0}" -f $err) -Level 'Error'

  Write-UiHeader -Title "Kill Switch"
  Write-UiLine -Text ("ERROR: {0}" -f $err) -Color Red
  throw
}
finally {
  # Always write console summary, even if an exception is thrown.
  try { Write-ConsoleSummary } catch { Write-Host "Summary failed: $($_.Exception.Message)" -ForegroundColor Yellow }
}

# Pipeline output: one structured object, no formatting
#[pscustomobject]$Run
