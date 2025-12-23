<#
.SYNOPSIS
Generates a compliance-style proof report for Microsoft Update Health Tools (UHT), Servicing Stack (SSU), and core Windows Update services, with optional remediation.

.DESCRIPTION
This script inspects the local system for:
- Microsoft Update Health Tools (installation presence and version).
- The Update Health service (uhssvc) configuration and state.
- Update Health scheduled tasks under a configurable task folder.
- Servicing Stack (SSU) version evidence (best-effort detection).
- Core Windows Update related services (state and startup type evidence).

The script produces:
- A human-friendly, colorized console summary (written only via host output).
- A JSON proof file with full evidence, notes, findings, and actions.
- A best-effort entry in the Windows Application Event Log (falls back to a text log file if Event Log write fails).

The pipeline output remains clean: the script emits exactly one structured object at the end, suitable for piping to Export-Csv, ConvertTo-Json, or Where-Object.

.PARAMETER CatalogPath
Optional path to a JSON catalog file that defines policy thresholds and proof output settings (for example minimum UHT/SSU versions, allowed service start modes, task folder, and proof output file path).

If CatalogPath is not specified or cannot be loaded, the script uses a built-in default catalog.

.PARAMETER Remediate
When set, the script attempts to remediate selected drifts (best-effort):
- Set startup type for the Update Health service (uhssvc) to the first allowed value from the catalog.
- Start/stop the service to match the desired state from the catalog.
- Enable scheduled tasks under the configured task folder.

No software installation is performed by this script.

.PARAMETER Strict
Controls how the final status is calculated:
- If Strict is not set: only Findings affect the final Status.
- If Strict is set: Notes are treated as Findings for status evaluation (for example, missing config/catalog paths can raise the overall Status).

.PARAMETER ConfigPath
Optional path to a JSON configuration file.
If present and readable, the script looks for a catalog path at:
  UpdateHealth.CatalogPath

If ConfigPath is missing/invalid, or if it does not contain UpdateHealth.CatalogPath, the script continues with the built-in default catalog.

.OUTPUTS
System.Management.Automation.PSCustomObject

A single object is emitted to the pipeline with the following properties:
- Status: 'OK' or 'WARNING'
- CatalogSource: Indicates which catalog source was used (Default, CatalogPath, ConfigPath->CatalogPath)
- Remediate: Boolean indicating whether remediation was enabled
- Strict: Boolean indicating whether Strict mode was enabled
- IsAdmin: Boolean indicating whether the script ran elevated
- JsonPath: Path to the written JSON proof file (best-effort)
- Findings: Array of finding objects (Time, Area, Severity, Message)
- Actions: Array of action objects (Time, Target, Operation, Result, Message)
- Notes: Array of note objects (same schema as Findings)
- DurationMs: Execution time in milliseconds

.NOTES
Behavior and conventions:
- Console output is intended for humans and is written via host output only; it is not emitted into the pipeline.
- JSON output is written best-effort; if writing fails, a note is added and a fallback log entry may be created.
- Event logging is best-effort; if Event Log source creation or write fails, the script writes a line to a fallback text log file.
- Some checks rely on best-effort evidence (for example SSU detection); when evidence cannot be determined, the script reports an appropriate note/finding instead of failing.

Exit behavior:
- The script is designed to complete and return a structured result even when some probes fail.
- Unhandled exceptions are captured and recorded as a runtime note/finding, then included in the output object.

.EXAMPLE
PS C:\> .\06-UpdateHealth-SSU-Proof.ps1

Runs in audit mode using default catalog behavior.
Writes a console summary, attempts to write the JSON proof, attempts Event Log write, and returns one object to the pipeline.

.EXAMPLE
PS C:\> .\06-UpdateHealth-SSU-Proof.ps1 -CatalogPath "PATH/TO/JSON/catalog.json"

Runs in audit mode using the specified catalog file.

.EXAMPLE
PS C:\> .\06-UpdateHealth-SSU-Proof.ps1 -ConfigPath "PATH/TO/JSON/config.json"

Runs in audit mode and tries to load the catalog path from UpdateHealth.CatalogPath inside the config file.
Falls back to the built-in catalog if the config or referenced catalog is unavailable.

.EXAMPLE
PS C:\> .\06-UpdateHealth-SSU-Proof.ps1 -Remediate

Runs in remediation mode (best-effort) and returns the actions taken in the output object.

.EXAMPLE
PS C:\> .\06-UpdateHealth-SSU-Proof.ps1 -Strict | Where-Object Status -ne 'OK'

Runs in strict mode and filters for non-OK outcomes using pipeline-safe output.

.EXAMPLE
PS C:\> .\06-UpdateHealth-SSU-Proof.ps1 | Select-Object Status,CatalogSource,JsonPath | Format-Table -AutoSize

Runs and displays only key output fields while preserving the full JSON proof file for details.
#>


[CmdletBinding()]
param(
  [string]$CatalogPath,
  [switch]$Remediate,
  [switch]$Strict,
  [string]$ConfigPath = "PATH/TO/JSON/config.json"
)

# ------------------------------------ Globals --------------------------------------
$script:EventSource = 'UpdateHealth-SSU-Proof'
$script:EventLog    = 'Application'
$script:FallbackLog = "PATH/TO/JSON/logs/UpdateHealth-SSU-Proof.log"

# -------------------------------- Console helpers ----------------------------------
function Write-UiLine {
  param(
    [string]$Text,
    [ValidateSet('Default','Info','Ok','Warn','Err','Dim','Header')]
    [string]$Style = 'Default'
  )

  $fg = $null
  switch ($Style) {
    'Header' { $fg = 'Cyan' }
    'Ok'     { $fg = 'Green' }
    'Info'   { $fg = 'Gray' }
    'Warn'   { $fg = 'Yellow' }
    'Err'    { $fg = 'Red' }
    'Dim'    { $fg = 'DarkGray' }
    default  { $fg = $null }
  }

  if ($fg) { Write-Host $Text -ForegroundColor $fg }  # Write-Host supports ForegroundColor.
  else { Write-Host $Text }
}

function Write-UiKeyValue {
  param(
    [string]$Key,
    [string]$Value,
    [ValidateSet('Default','Info','Ok','Warn','Err','Dim')]
    [string]$Style = 'Default'
  )
  Write-UiLine -Text ("{0,-12}: {1}" -f $Key,$Value) -Style $Style
}

# ------------------------------------ Helpers --------------------------------------
function Ensure-Dir {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Write-FallbackLogLine {
  param([string]$Line)
  try {
    Ensure-Dir (Split-Path -Parent $script:FallbackLog)
    ("{0} {1}" -f (Get-Date).ToString('s'), $Line) | Out-File -FilePath $script:FallbackLog -Encoding UTF8 -Append
  } catch { }
}

function Ensure-EventSource {
  param(
    [string]$Source = $script:EventSource,
    [string]$Log    = $script:EventLog
  )
  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
      New-EventLog -LogName $Log -Source $Source -ErrorAction Stop
    }
    return $true
  } catch {
    Write-FallbackLogLine ("EventSource init failed (Source={0}, Log={1}): {2}" -f $Source,$Log,$_.Exception.Message)
    return $false
  }
}

function Write-HealthEvent {
  param(
    [int]$Id,
    [string]$Msg,
    [ValidateSet('Information','Warning','Error')]
    [string]$Level = 'Information',
    [string]$Source = $script:EventSource,
    [string]$LogName = $script:EventLog
  )
  try {
    Write-EventLog -LogName $LogName -Source $Source -EntryType $Level -EventId $Id -Message $Msg -ErrorAction Stop
    return $true
  } catch {
    Write-FallbackLogLine ("EventLog write failed ({0}/{1}): {2} | Error: {3}" -f $Level,$Id,$Msg,$_.Exception.Message)
    return $false
  }
}

function Is-Admin {
  try {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

function Save-Json {
  param([object]$Obj,[string]$Path)
  try {
    Ensure-Dir (Split-Path -Parent $Path)
    ($Obj | ConvertTo-Json -Depth 12) | Out-File -Encoding UTF8 -FilePath $Path
    return $true
  } catch {
    Write-FallbackLogLine ("JSON write failed ({0}): {1}" -f $Path,$_.Exception.Message)
    return $false
  }
}

function Get-SafeString {
  param($Value,[string]$Default)
  if ($Value -eq $null) { return $Default }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $Default }
  return $s
}

function Normalize-VersionString {
  param([string]$s)
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }

  $t = $s -replace '[A-Za-z_-]',' '
  $t = ($t -replace '[^\d\.]',' ').Trim()

  $m = [regex]::Matches($t,'\d+(\.\d+){1,3}') |
    Sort-Object { $_.Value.Length } -Descending |
    Select-Object -First 1

  if ($m) { try { return [version]$m.Value } catch { return $null } }
  try { return [version]$s } catch { return $null }
}

function Compare-Version {
  param([string]$a,[string]$b)
  $va = Normalize-VersionString $a
  $vb = Normalize-VersionString $b
  if (-not $va -or -not $vb) { return $null }
  if     ($va -lt $vb) { return -1 }
  elseif ($va -gt $vb) { return  1 }
  else                 { return  0 }
}

function New-Finding {
  param([string]$Area,[ValidateSet('Info','Warning','Error')][string]$Severity,[string]$Message)
  [pscustomobject]@{
    Time     = (Get-Date).ToString('s')
    Area     = $Area
    Severity = $Severity
    Message  = $Message
  }
}

function New-Action {
  param([string]$Target,[string]$Operation,[ValidateSet('Success','Failed')][string]$Result,[string]$Message)
  [pscustomobject]@{
    Time      = (Get-Date).ToString('s')
    Target    = $Target
    Operation = $Operation
    Result    = $Result
    Message   = $Message
  }
}

function Add-ArrayList {
  param([System.Collections.ArrayList]$List,$Item)
  [void]$List.Add($Item)
}

function Add-ArrayListMany {
  param([System.Collections.ArrayList]$List,$Items)
  if ($Items -eq $null) { return }
  foreach($i in @($Items)) { [void]$List.Add($i) }
}

# -------------------------------- Service/Tasks helpers -----------------------------
function Set-ServiceStartType {
  param(
    [string]$Name,
    [ValidateSet('Disabled','Manual','Automatic','AutomaticDelayedStart')]
    [string]$StartType
  )

  $actions = New-Object System.Collections.ArrayList

  try {
    if ($StartType -eq 'AutomaticDelayedStart') {
      $p = Start-Process -FilePath "$env:windir\System32\sc.exe" -ArgumentList @("config",$Name,"start=","delayed-auto") -NoNewWindow -Wait -PassThru -ErrorAction Stop
      if ($p.ExitCode -ne 0) { throw ("sc.exe exit code {0}" -f $p.ExitCode) }
      Add-ArrayList $actions (New-Action -Target $Name -Operation 'SetStartupType' -Result 'Success' -Message 'AutomaticDelayedStart (sc.exe delayed-auto)')
    } else {
      Set-Service -Name $Name -StartupType $StartType -ErrorAction Stop
      Add-ArrayList $actions (New-Action -Target $Name -Operation 'SetStartupType' -Result 'Success' -Message $StartType)
    }
  } catch {
    Add-ArrayList $actions (New-Action -Target $Name -Operation 'SetStartupType' -Result 'Failed' -Message $_.Exception.Message)
  }

  return $actions
}

function Ensure-ServiceState {
  param(
    [string]$Name,
    [ValidateSet('Disabled','Manual','Automatic','AutomaticDelayedStart')]
    [string]$Start,
    [ValidateSet('Running','Stopped')]
    [string]$State,
    [switch]$Remediate
  )

  $drift   = New-Object System.Collections.ArrayList
  $actions = New-Object System.Collections.ArrayList
  $ok = $true

  try {
    $svc = Get-Service -Name $Name -ErrorAction Stop
    $actualStart = $svc.StartType.ToString()
    $actualState = $svc.Status.ToString()

    if ($actualStart -ne $Start) {
      $ok = $false
      Add-ArrayList $drift (New-Finding -Area ("Service:{0}" -f $Name) -Severity 'Warning' -Message ("StartType={0} expected={1}" -f $actualStart,$Start))
      if ($Remediate) { Add-ArrayListMany $actions (Set-ServiceStartType -Name $Name -StartType $Start) }
    }

    if ($actualState -ne $State) {
      $ok = $false
      Add-ArrayList $drift (New-Finding -Area ("Service:{0}" -f $Name) -Severity 'Warning' -Message ("State={0} expected={1}" -f $actualState,$State))
      if ($Remediate) {
        try {
          if ($State -eq 'Running') { Start-Service -Name $Name -ErrorAction Stop }
          else { Stop-Service -Name $Name -Force -ErrorAction Stop }
          Add-ArrayList $actions (New-Action -Target $Name -Operation 'SetState' -Result 'Success' -Message $State)
        } catch {
          Add-ArrayList $actions (New-Action -Target $Name -Operation 'SetState' -Result 'Failed' -Message $_.Exception.Message)
        }
      }
    }

  } catch {
    $ok = $false
    Add-ArrayList $drift (New-Finding -Area ("Service:{0}" -f $Name) -Severity 'Error' -Message ("Not found or inaccessible: {0}" -f $_.Exception.Message))
  }

  [pscustomobject]@{ Ok=$ok; Drift=$drift; Actions=$actions }
}

function Get-TaskInfoUnder {
  param([string]$Folder)

  $list = New-Object System.Collections.ArrayList
  try {
    $tasks = Get-ScheduledTask -TaskPath $Folder -ErrorAction Stop
    foreach($t in $tasks){
      $state = "Unknown"
      try { $state = (Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop).State.ToString() } catch { }
      Add-ArrayList $list ([pscustomobject]@{
        Path    = ($t.TaskPath + $t.TaskName)
        Enabled = [bool]$t.Enabled
        State   = $state
      })
    }
  } catch { }
  return $list
}

function Ensure-TasksEnabled {
  param([string]$Folder,[switch]$Remediate)

  $drift   = New-Object System.Collections.ArrayList
  $actions = New-Object System.Collections.ArrayList
  $ok = $true

  try {
    $tasks = Get-ScheduledTask -TaskPath $Folder -ErrorAction Stop
    foreach($t in $tasks){
      if (-not $t.Enabled) {
        $ok = $false
        Add-ArrayList $drift (New-Finding -Area ("Task:{0}{1}" -f $t.TaskPath,$t.TaskName) -Severity 'Warning' -Message 'Disabled')
        if ($Remediate) {
          try {
            Enable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
            Add-ArrayList $actions (New-Action -Target ("{0}{1}" -f $t.TaskPath,$t.TaskName) -Operation 'EnableTask' -Result 'Success' -Message 'Enabled')
          } catch {
            Add-ArrayList $actions (New-Action -Target ("{0}{1}" -f $t.TaskPath,$t.TaskName) -Operation 'EnableTask' -Result 'Failed' -Message $_.Exception.Message)
          }
        }
      }
    }
  } catch {
    $ok = $false
    Add-ArrayList $drift (New-Finding -Area ("TaskFolder:{0}" -f $Folder) -Severity 'Error' -Message $_.Exception.Message)
  }

  [pscustomobject]@{ Ok=$ok; Drift=$drift; Actions=$actions }
}

# ------------------------------------ Catalog defaults -----------------------------
$DefaultCatalog = @"
{
  "UpdateHealthTools": {
    "Require": true,
    "MinVersion": "5.0.0.0",
    "ServiceStartAllowed": ["Automatic","AutomaticDelayedStart"],
    "ServiceDesiredState": "Running",
    "EnsureTasksEnabled": true,
    "TaskFolder": "\\Microsoft\\UpdateHealthService\\"
  },
  "ServicingStack": {
    "MinVersion": "10.0.22621.3800"
  },
  "Proof": {
    "OutFile": "PATH/TO/JSON/proof/UpdateHealth-SSU-Proof.json"
  }
}
"@ | ConvertFrom-Json

function Load-Catalog {
  param([string]$CatalogPath,[string]$ConfigPath,[object]$FallbackCatalog)

  $meta = [pscustomobject]@{
    CatalogLoaded = $false
    CatalogSource = 'Default'
    Errors        = @()
  }

  if ($CatalogPath) {
    if (Test-Path -LiteralPath $CatalogPath) {
      try {
        $cat = Get-Content -Raw -LiteralPath $CatalogPath | ConvertFrom-Json -ErrorAction Stop
        $meta.CatalogLoaded = $true
        $meta.CatalogSource = 'CatalogPath'
        return [pscustomobject]@{ Catalog=$cat; Meta=$meta }
      } catch {
        $meta.Errors += ("CatalogPath JSON parse failed: {0}" -f $_.Exception.Message)
      }
    } else {
      $meta.Errors += "CatalogPath not found."
    }
  }

  if ($ConfigPath) {
    if (Test-Path -LiteralPath $ConfigPath) {
      try {
        $cfg = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json -ErrorAction Stop
        $p = $null
        if ($cfg -and $cfg.UpdateHealth -and $cfg.UpdateHealth.CatalogPath) { $p = [string]$cfg.UpdateHealth.CatalogPath }
        if ($p) {
          if (Test-Path -LiteralPath $p) {
            $cat = Get-Content -Raw -LiteralPath $p | ConvertFrom-Json -ErrorAction Stop
            $meta.CatalogLoaded = $true
            $meta.CatalogSource = 'ConfigPath->CatalogPath'
            return [pscustomobject]@{ Catalog=$cat; Meta=$meta }
          } else {
            $meta.Errors += "Config points to catalog path, but it was not found."
          }
        } else {
          $meta.Errors += "Config JSON has no UpdateHealth.CatalogPath."
        }
      } catch {
        $meta.Errors += ("Config JSON parse failed: {0}" -f $_.Exception.Message)
      }
    } else {
      $meta.Errors += "ConfigPath not found."
    }
  }

  return [pscustomobject]@{ Catalog=$FallbackCatalog; Meta=$meta }
}

# ------------------------------------ Probes ---------------------------------------
function Get-UHT-Info {
  $ret = [ordered]@{
    Installed       = $false
    DisplayName     = $null
    DisplayVersion  = $null
    InstallDate     = $null
    InstallLocation = $null
    Service         = $null
    Tasks           = @()
    FileVersion     = $null
  }

  $keys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  )

  $hit = $null
  foreach($k in $keys){
    try {
      foreach($i in (Get-ChildItem -LiteralPath $k -ErrorAction Stop)){
        $p = Get-ItemProperty -LiteralPath $i.PSPath -ErrorAction SilentlyContinue
        if ($p.DisplayName -match 'Microsoft Update Health Tools') { $hit=$p; break }
      }
      if ($hit){ break }
    } catch { }
  }

  if ($hit){
    $ret.Installed       = $true
    $ret.DisplayName     = $hit.DisplayName
    $ret.DisplayVersion  = $hit.DisplayVersion
    $ret.InstallDate     = $hit.InstallDate
    $ret.InstallLocation = $hit.InstallLocation
  }

  $baseDirs = @(
    "$env:ProgramFiles\Microsoft Update Health Tools",
    "$env:ProgramFiles(x86)\Microsoft Update Health Tools"
  )

  foreach($d in $baseDirs){
    if ($ret.FileVersion) { break }
    try {
      if (Test-Path -LiteralPath $d) {
        $exe = Get-ChildItem -LiteralPath $d -Filter *.exe -Recurse -File -ErrorAction SilentlyContinue |
          Sort-Object { $_.VersionInfo.FileVersionRaw } -Descending |
          Select-Object -First 1
        if ($exe) { $ret.FileVersion = $exe.VersionInfo.FileVersion }
        if (-not $ret.InstallLocation) { $ret.InstallLocation = $d }
      }
    } catch { }
  }

  try {
    $svc = Get-Service -Name 'uhssvc' -ErrorAction Stop
    $ret.Service = [ordered]@{
      Name      = $svc.Name
      StartType = $svc.StartType.ToString()
      Status    = $svc.Status.ToString()
    }
  } catch {
    $ret.Service = [ordered]@{ Name='uhssvc'; StartType='N/A'; Status='N/A' }
  }

  $ret.Tasks = Get-TaskInfoUnder '\Microsoft\UpdateHealthService\'
  return $ret
}

function Get-SSU-Info {
  $ret = [ordered]@{
    Version         = $null
    Source          = $null
    PackageIdentity = $null
    InstalledOn     = $null
  }

  try {
    $reg1 = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\Servicing' -ErrorAction Stop
    $v = $reg1.ServicingStackVersion
    if ($v) {
      $ret.Version = [string]$v
      $ret.Source  = 'Registry:ServicingStackVersion'
      return $ret
    }
  } catch { }

  try {
    $out = (& dism.exe /online /get-packages /format:table 2>&1) | Out-String
    $lines = $out -split "`r?`n"
    $line = $lines | Where-Object { $_ -match 'Package_for_ServicingStack' } | Select-Object -First 1
    if ($line) {
      $id = ($line -replace '^\s*\|\s*','') -replace '\s*\|\s*.*$',''
      $id = $id.Trim()
      if ([string]::IsNullOrWhiteSpace($id)) { $id = ($line -replace '.*:\s*','').Trim() }

      $ret.PackageIdentity = $id
      $ver = Normalize-VersionString $id
      if ($ver) { $ret.Version = $ver.ToString() }
      $ret.Source = 'DISM:Get-Packages'
    }
  } catch { }

  return $ret
}

function Get-WU-CoreServices {
  $names = @('UsoSvc','WaaSMedicSvc','wuauserv','DoSvc','BITS','cryptsvc')
  $list = New-Object System.Collections.ArrayList
  foreach($n in $names){
    try {
      $s = Get-Service -Name $n -ErrorAction Stop
      Add-ArrayList $list ([pscustomobject]@{ Name=$n; StartType=$s.StartType.ToString(); Status=$s.Status.ToString() })
    } catch {
      Add-ArrayList $list ([pscustomobject]@{ Name=$n; StartType='N/A'; Status='N/A' })
    }
  }
  return $list
}

# ------------------------------------ Main -----------------------------------------
$sw = New-Object System.Diagnostics.Stopwatch
$sw.Start()

$admin = Is-Admin
$eventSourceOk = Ensure-EventSource

$findings = New-Object System.Collections.ArrayList
$actions  = New-Object System.Collections.ArrayList
$notes    = New-Object System.Collections.ArrayList

$outFile = "PATH/TO/JSON/proof/UpdateHealth-SSU-Proof.json"
$catalogInfo = $null
$evidence = [ordered]@{}

try {
  if (-not $admin) {
    Add-ArrayList $notes (New-Finding -Area 'Runtime' -Severity 'Info' -Message 'Not elevated; remediation/event logging may fail.')
  }

  $loaded = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath -FallbackCatalog $DefaultCatalog
  $cat  = $loaded.Catalog
  $meta = $loaded.Meta
  $catalogInfo = $meta

  if (-not $meta.CatalogLoaded -and $meta.Errors -and $meta.Errors.Count -gt 0) {
    foreach($e in $meta.Errors) { Add-ArrayList $notes (New-Finding -Area 'Catalog' -Severity 'Info' -Message $e) }
  }

  # UHT
  $u = Get-UHT-Info
  $evidence.UpdateHealthTools = $u

  $uhtRequire = $true
  if ($cat -and $cat.UpdateHealthTools -and ($cat.UpdateHealthTools.Require -ne $null)) { $uhtRequire = [bool]$cat.UpdateHealthTools.Require }

  if ($uhtRequire -and -not $u.Installed) {
    Add-ArrayList $findings (New-Finding -Area 'UHT' -Severity 'Error' -Message 'Not installed.')
  }

  $minUht = $null
  if ($cat -and $cat.UpdateHealthTools -and $cat.UpdateHealthTools.MinVersion) { $minUht = [string]$cat.UpdateHealthTools.MinVersion }
  if ($minUht) {
    $have = $u.DisplayVersion
    $haveSrc = 'DisplayVersion'
    if ([string]::IsNullOrWhiteSpace($have)) { $have = $u.FileVersion; $haveSrc = 'FileVersion' }

    if ($have) {
      $cmp = Compare-Version $have $minUht
      if ($cmp -eq $null) {
        Add-ArrayList $findings (New-Finding -Area 'UHT' -Severity 'Warning' -Message ("Version compare failed ({0}='{1}' vs Min='{2}')." -f $haveSrc,$have,$minUht))
      } elseif ($cmp -lt 0) {
        Add-ArrayList $findings (New-Finding -Area 'UHT' -Severity 'Warning' -Message ("{0} {1} < Min {2}." -f $haveSrc,$have,$minUht))
      }
    } elseif ($uhtRequire) {
      Add-ArrayList $findings (New-Finding -Area 'UHT' -Severity 'Warning' -Message ("Version unknown; cannot compare to Min {0}." -f $minUht))
    }
  }

  if ($u.Installed) {
    $allowed = @('Automatic','AutomaticDelayedStart')
    if ($cat -and $cat.UpdateHealthTools -and $cat.UpdateHealthTools.ServiceStartAllowed) {
      try { $allowed = @($cat.UpdateHealthTools.ServiceStartAllowed) } catch { }
      if (-not $allowed -or $allowed.Count -eq 0) { $allowed = @('Automatic','AutomaticDelayedStart') }
    }

    $desiredState = 'Running'
    if ($cat -and $cat.UpdateHealthTools -and $cat.UpdateHealthTools.ServiceDesiredState) {
      $desiredState = Get-SafeString $cat.UpdateHealthTools.ServiceDesiredState 'Running'
    }

    $svcStartActual  = $u.Service.StartType
    $svcStatusActual = $u.Service.Status

    if ($svcStartActual -and $svcStartActual -ne 'N/A' -and ($allowed -notcontains $svcStartActual)) {
      Add-ArrayList $findings (New-Finding -Area 'UHT' -Severity 'Warning' -Message ("uhssvc StartType '{0}' not allowed ({1})." -f $svcStartActual,($allowed -join ', ')))
      if ($Remediate) {
        $svcFix = Ensure-ServiceState -Name 'uhssvc' -Start $allowed[0] -State $desiredState -Remediate:$true
        Add-ArrayListMany $findings $svcFix.Drift
        Add-ArrayListMany $actions  $svcFix.Actions
      }
    } else {
      if ($svcStatusActual -and $svcStatusActual -ne 'N/A' -and $svcStatusActual -ne $desiredState) {
        Add-ArrayList $findings (New-Finding -Area 'UHT' -Severity 'Warning' -Message ("uhssvc Status '{0}' expected '{1}'." -f $svcStatusActual,$desiredState))
        if ($Remediate) {
          $startToUse = $allowed[0]
          if ($svcStartActual -and ($allowed -contains $svcStartActual)) { $startToUse = $svcStartActual }
          $svcFix = Ensure-ServiceState -Name 'uhssvc' -Start $startToUse -State $desiredState -Remediate:$true
          Add-ArrayListMany $findings $svcFix.Drift
          Add-ArrayListMany $actions  $svcFix.Actions
        }
      }
    }

    $ensureTasks = $true
    if ($cat -and $cat.UpdateHealthTools -and ($cat.UpdateHealthTools.EnsureTasksEnabled -ne $null)) { $ensureTasks = [bool]$cat.UpdateHealthTools.EnsureTasksEnabled }
    if ($ensureTasks) {
      $taskFolder = '\Microsoft\UpdateHealthService\'
      if ($cat -and $cat.UpdateHealthTools -and $cat.UpdateHealthTools.TaskFolder) { $taskFolder = [string]$cat.UpdateHealthTools.TaskFolder }

      $evidence.UpdateHealthTools.Tasks = Get-TaskInfoUnder $taskFolder

      $tFix = Ensure-TasksEnabled -Folder $taskFolder -Remediate:$Remediate
      Add-ArrayListMany $findings $tFix.Drift
      Add-ArrayListMany $actions  $tFix.Actions
    }
  }

  # SSU
  $s = Get-SSU-Info
  $evidence.ServicingStack = $s

  $minSsu = $null
  if ($cat -and $cat.ServicingStack -and $cat.ServicingStack.MinVersion) { $minSsu = [string]$cat.ServicingStack.MinVersion }
  if ($minSsu) {
    if ($s.Version) {
      $cmp = Compare-Version $s.Version $minSsu
      if ($cmp -eq $null) {
        Add-ArrayList $findings (New-Finding -Area 'SSU' -Severity 'Warning' -Message ("Version compare failed (Have='{0}' vs Min='{1}', Source={2})." -f $s.Version,$minSsu,$s.Source))
      } elseif ($cmp -lt 0) {
        Add-ArrayList $findings (New-Finding -Area 'SSU' -Severity 'Warning' -Message ("{0} < Min {1} (Source={2})." -f $s.Version,$minSsu,$s.Source))
      }
    } else {
      Add-ArrayList $findings (New-Finding -Area 'SSU' -Severity 'Warning' -Message ("Version unknown; cannot compare to Min {0}." -f $minSsu))
    }
  }

  # Core services
  $evidence.WUCoreServices = Get-WU-CoreServices

  # Proof path
  if ($cat -and $cat.Proof -and $cat.Proof.OutFile) { $outFile = [string]$cat.Proof.OutFile }

} catch {
  Add-ArrayList $notes (New-Finding -Area 'Runtime' -Severity 'Error' -Message ("Fatal error: {0}" -f $_.Exception.Message))
}

# Strict: treat notes as findings
$effectiveFindings = New-Object System.Collections.ArrayList
Add-ArrayListMany $effectiveFindings $findings
if ($Strict) { Add-ArrayListMany $effectiveFindings $notes }

# Compose proof object
$proof = [pscustomobject]@{
  Time        = (Get-Date).ToString('s')
  Hostname    = $env:COMPUTERNAME
  User        = [pscustomobject]@{ Name=$env:USERNAME; IsAdmin=$admin }
  Settings    = [pscustomobject]@{
    CatalogPath = (Get-SafeString $CatalogPath '')
    ConfigPath  = (Get-SafeString $ConfigPath '')
    Remediate   = [bool]$Remediate
    Strict      = [bool]$Strict
    EventSource = $script:EventSource
    EventLog    = $script:EventLog
    FallbackLog = $script:FallbackLog
  }
  CatalogMeta = $catalogInfo
  Evidence    = $evidence
  Actions     = @($actions)
  Findings    = @($effectiveFindings)
  Notes       = @($notes)
}

# Persist JSON
$jsonOk = Save-Json -Obj $proof -Path $outFile
if ($jsonOk) { Add-ArrayList $actions (New-Action -Target $outFile -Operation 'WriteJson' -Result 'Success' -Message 'Proof written') }
else { Add-ArrayList $notes (New-Finding -Area 'Proof' -Severity 'Info' -Message 'Failed to write JSON proof file.') }

# Event log (best effort)
if ($eventSourceOk) {
  $hasFinding = ($effectiveFindings.Count -gt 0)
  $evtId = if ($hasFinding) { 5010 } else { 5000 }
  $evtLevel = if ($hasFinding) { 'Warning' } else { 'Information' }

  $catalogSource = 'Default'
  if ($catalogInfo -and $catalogInfo.CatalogSource) { $catalogSource = [string]$catalogInfo.CatalogSource }

  $top = @()
  foreach($f in @($effectiveFindings)) { if ($top.Count -ge 8) { break } $top += ("[{0}] {1}" -f $f.Area,$f.Message) }

  $evtMsg = @(
    ("CatalogSource={0}; Remediate={1}; Strict={2}; Admin={3}; JSON={4}" -f $catalogSource,[bool]$Remediate,[bool]$Strict,$admin,$outFile),
    ("Actions={0}; Findings={1}" -f $actions.Count,$effectiveFindings.Count),
    ("Top={0}" -f ($top -join ' | '))
  ) -join "`r`n"

  [void](Write-HealthEvent -Id $evtId -Msg $evtMsg -Level $evtLevel)
}

$sw.Stop()

# ----------------------------- Pretty console summary -------------------------------
$catalogSource2 = 'Default'
if ($catalogInfo -and $catalogInfo.CatalogSource) { $catalogSource2 = [string]$catalogInfo.CatalogSource }

$summaryStatus = if ($effectiveFindings.Count -gt 0) { 'WARNING' } else { 'OK' }

$summaryStyle = 'Ok'
if ($summaryStatus -ne 'OK') { $summaryStyle = 'Warn' }

$adminStyle = 'Warn'
if ($admin) { $adminStyle = 'Ok' }

Write-Host ""
Write-UiLine -Text "=== UpdateHealth/SSU Proof Summary ===" -Style 'Header'
Write-UiKeyValue -Key 'Status'    -Value $summaryStatus -Style $summaryStyle
Write-UiKeyValue -Key 'Remediate' -Value ([string][bool]$Remediate) -Style 'Dim'
Write-UiKeyValue -Key 'Strict'    -Value ([string][bool]$Strict) -Style 'Dim'
Write-UiKeyValue -Key 'Admin'     -Value ([string]$admin) -Style $adminStyle
Write-UiKeyValue -Key 'Catalog'   -Value $catalogSource2 -Style 'Dim'
Write-UiKeyValue -Key 'JSON'      -Value $outFile -Style 'Dim'
Write-UiKeyValue -Key 'EventLog'  -Value ("{0}/{1}" -f $script:EventLog,$script:EventSource) -Style 'Dim'
Write-UiKeyValue -Key 'Duration'  -Value ("{0} ms" -f $sw.ElapsedMilliseconds) -Style 'Dim'

if ($notes.Count -gt 0) {
  Write-Host ""
  Write-UiLine -Text "Notes" -Style 'Header'
  foreach($n in @($notes)) {
    $st = 'Info'
    if ($n.Severity -eq 'Error') { $st = 'Err' }
    elseif ($n.Severity -eq 'Warning') { $st = 'Warn' }
    Write-UiLine -Text ("- {0} [{1}] {2}" -f $n.Time,$n.Area,$n.Message) -Style $st
  }
}

if ($actions.Count -gt 0) {
  Write-Host ""
  Write-UiLine -Text "Actions" -Style 'Header'
  foreach($a in @($actions)) {
    $st2 = 'Ok'
    if ($a.Result -ne 'Success') { $st2 = 'Err' }
    Write-UiLine -Text ("- {0} {1} {2}: {3} ({4})" -f $a.Time,$a.Target,$a.Operation,$a.Message,$a.Result) -Style $st2
  }
}

if ($effectiveFindings.Count -gt 0) {
  Write-Host ""
  Write-UiLine -Text "Findings" -Style 'Header'
  foreach($f in @($effectiveFindings)) {
    $st3 = 'Info'
    if ($f.Severity -eq 'Error') { $st3 = 'Err' }
    elseif ($f.Severity -eq 'Warning') { $st3 = 'Warn' }
    Write-UiLine -Text ("- {0} [{1}] {2} ({3})" -f $f.Time,$f.Area,$f.Message,$f.Severity) -Style $st3
  }
} else {
  Write-Host ""
  Write-UiLine -Text "No findings." -Style 'Ok'
}

# ----------------------------- Pipeline output (single object) ---------------------
# [pscustomobject]@{
#   Status        = $summaryStatus
#   CatalogSource = $catalogSource2
#   Remediate     = [bool]$Remediate
#   Strict        = [bool]$Strict
#   IsAdmin       = $admin
#   JsonPath      = $outFile
#   Findings      = @($effectiveFindings)
#   Actions       = @($actions)
#   Notes         = @($notes)
#   DurationMs    = $sw.ElapsedMilliseconds
# }
