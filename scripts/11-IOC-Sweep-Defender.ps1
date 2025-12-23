<#
.SYNOPSIS
  Performs an IOC (Indicator of Compromise) sweep on the local Windows host, optionally runs a Microsoft Defender on-demand scan, optionally collects evidence, and writes an audit-ready JSON proof file.

.DESCRIPTION
  This script loads an IOC catalog from JSON (or uses a built-in default catalog if no JSON is available), then evaluates multiple IOC types on the local system.

  Covered IOC checks:
  - Files: exact file paths validated by SHA256 hash and/or certificate publisher (Authenticode).
  - FileGlobs: wildcard patterns resolved to files, then validated by SHA256 hash and/or publisher.
  - Registry: registry value presence with optional data regex match.
  - Services: service existence with optional image path regex match.
  - ScheduledTasks: tasks matched by regex against full task path + name.
  - Processes: running processes matched by image path regex and optional publisher constraint.
  - Network: remote IP matches against established TCP connections; domain matches against the DNS client cache.

  Optional actions:
  - Defender scan: Quick/Full scan, or Custom scan for specific paths when ScanType is set to None and CustomScanPaths are provided.
  - Evidence collection: copies matched files and exports registry keys to an evidence directory.
  - Remediation: non-destructive containment actions based on catalog rule actions (for example: disable a task, stop/disable a service, remove a registry value when Action=neutralize).

  Output behavior:
  - The script prints a human-friendly, colorized summary to the console.
  - The script writes a JSON proof file that contains parameters, scan results, findings, actions taken, errors, and a summary.
  - By default, the script does not write objects to the success pipeline (to keep pipelines clean); use -PassThru to output the final Proof object.

.PARAMETER CatalogPath
  Path to an IOC catalog JSON file.
  If specified and loadable, this catalog is used.

.PARAMETER ConfigPath
  Path to a configuration JSON file that can provide a catalog location (expected property: IOC.CatalogPath).
  If CatalogPath is not provided or cannot be loaded, the script attempts to read ConfigPath and then load the catalog from IOC.CatalogPath.

.PARAMETER ScanType
  Controls Microsoft Defender scan execution.
  Valid values:
  - Full  : Runs a Defender full scan.
  - Quick : Runs a Defender quick scan.
  - None  : Skips standard scan types; can still perform custom scans if CustomScanPaths are provided.

.PARAMETER CustomScanPaths
  One or more file/folder paths to scan with Microsoft Defender custom scan mode.
  Used only when ScanType is set to None.
  Environment variables in paths are expanded before validation.

.PARAMETER CollectEvidence
  Enables evidence collection for matched IOCs.
  Evidence collection includes:
  - Copying matched files into the evidence directory.
  - Exporting registry keys (containing matched values) into .reg files.

.PARAMETER Remediate
  Enables remediation/containment actions for matched IOCs when the corresponding catalog rule requests an action.
  Actions are intentionally non-destructive and limited to:
  - Services: stop and/or disable (based on rule action).
  - Scheduled tasks: disable (based on rule action).
  - Registry values: remove only when Action is exactly 'neutralize'.

.PARAMETER Strict
  Controls the overall "signal" behavior.
  When enabled, the script will treat the run as noteworthy even if there are no findings (for example, for compliance/audit runs), and will emit the warning event path instead of the OK event path.

.PARAMETER PassThru
  Outputs the final Proof object to the success pipeline.
  Use this when you want to programmatically consume results, for example:
  - ConvertTo-Json
  - Export-Csv
  - Where-Object filtering

.OUTPUTS
  By default: none (no objects are written to the success pipeline).
  With -PassThru: a single structured object (the Proof object) containing:
  - Runtime context (time, hostname, user, admin state)
  - Input parameters
  - Catalog source metadata
  - Defender scan result (if executed)
  - Findings by category
  - Actions performed
  - Errors encountered
  - Summary including ExitCode

.NOTES
  Catalog loading fallback order:
  1) CatalogPath (if provided and readable)
  2) ConfigPath -> IOC.CatalogPath (if provided and readable)
  3) Built-in default catalog (empty rule sets)

  Exit codes:
  - 0: No findings and no errors.
  - 1: Findings and/or errors occurred (or Strict triggered a non-OK outcome).

  Evidence handling:
  - Evidence collection is best-effort; failures to copy/export are recorded in the proof Errors array.
  - Evidence paths are stored in findings when available.

  Console output:
  - The console summary is intended for operators and is produced via host-only output functions.
  - Structured results are persisted to JSON and optionally emitted via -PassThru.

.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1

  Runs the sweep with the default scan type (Full) and uses JSON configuration/catalog if available; otherwise uses the built-in default catalog.
  Writes the proof JSON file and prints the console summary.

.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -CatalogPath "PATH/TO/JSON/ioc-catalog.json" -CollectEvidence

  Loads a specific IOC catalog and collects evidence for any matches.

.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -ScanType Quick

  Runs the IOC sweep and performs a Defender quick scan.

.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -ScanType None -CustomScanPaths "C:\Temp","C:\Users\Public" -CollectEvidence

  Runs the IOC sweep and performs Defender custom scans of the specified paths, then collects evidence for any IOC matches.

.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -Remediate -Strict

  Runs the sweep and applies non-destructive remediation actions as defined by the catalog rules.
  Strict mode forces a "noteworthy" run classification even if no findings are detected.

.EXAMPLE
  $proof = .\11-IOC-Sweep-Defender.ps1 -PassThru
  $proof.Findings.Files | Where-Object { $_.Signed -eq $false } | ConvertTo-Json -Depth 5

  Runs the sweep and returns the proof object for further filtering and conversion.

#>


[CmdletBinding()]
param(
  [string]$CatalogPath,
  [switch]$Remediate,
  [switch]$CollectEvidence,
  [ValidateSet('Quick','Full','None')] [string]$ScanType = 'Full',
  [string[]]$CustomScanPaths,
  [switch]$Strict,
  [string]$ConfigPath = "PATH/TO/JSON/config.json",
  [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

# -----------------------------
# Globals / Defaults (anonymized)
# -----------------------------
$EventSource  = 'IOC-Sweep-Defender'
$EventLogName = 'Application'

$DefaultProofOutFile = "PATH/TO/PROOF/IOC-Sweep.json"
$DefaultEvidenceDir  = "PATH/TO/EVIDENCE"

# -----------------------------
# Console helpers (host-only)
# -----------------------------
function Write-UiLine {
  param(
    [Parameter(Mandatory=$true)][string]$Text,
    [ConsoleColor]$Color = [ConsoleColor]::Gray,
    [switch]$NoNewLine
  )
  if ($NoNewLine) { Write-Host $Text -ForegroundColor $Color -NoNewline }
  else { Write-Host $Text -ForegroundColor $Color }
}

function Write-UiRule {
  param([ConsoleColor]$Color = [ConsoleColor]::DarkGray)
  Write-UiLine ("=" * 78) $Color
}

function Write-UiHeader {
  param([string]$Text)
  Write-Host ""
  Write-UiRule DarkGray
  Write-UiLine ("  " + $Text) Cyan
  Write-UiRule DarkGray
}

function Write-UiKV {
  param(
    [string]$Key,
    [string]$Value,
    [ConsoleColor]$ValueColor = [ConsoleColor]::Gray
  )
  $k = ("{0,-14}" -f ($Key + ":"))
  Write-UiLine $k DarkGray -NoNewLine
  Write-UiLine $Value $ValueColor
}

function Write-UiStatus {
  param(
    [string]$Label,
    [ValidateSet('OK','WARN','FAIL','INFO')] [string]$State,
    [string]$Detail = ""
  )

  $stateColor = [ConsoleColor]::Gray
  switch ($State) {
    'OK'   { $stateColor = [ConsoleColor]::Green }
    'WARN' { $stateColor = [ConsoleColor]::Yellow }
    'FAIL' { $stateColor = [ConsoleColor]::Red }
    'INFO' { $stateColor = [ConsoleColor]::Cyan }
  }

  Write-UiLine ("[{0}]" -f $State) $stateColor -NoNewLine
  Write-UiLine (" {0}" -f $Label) White -NoNewLine
  if ($Detail) { Write-UiLine (" - {0}" -f $Detail) DarkGray } else { Write-Host "" }
}

function Write-UiBullet {
  param([string]$Text,[ConsoleColor]$Color = [ConsoleColor]::Gray)
  Write-UiLine ("  - " + $Text) $Color
}

function Write-Info {
  param([string]$Message)
  # In Windows PowerShell 5.1 the information stream is often suppressed by default; force visibility.
  Write-Information -MessageData $Message -InformationAction Continue
}

# -----------------------------
# Core helpers
# -----------------------------
function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Ensure-EventSource {
  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
      if (Test-IsAdmin) {
        New-EventLog -LogName $EventLogName -Source $EventSource -ErrorAction Stop
      }
    }
  } catch { }
}

function Write-HealthEvent {
  param(
    [int]$Id,
    [string]$Msg,
    [ValidateSet('Information','Warning','Error')] [string]$Level='Information'
  )
  try {
    Write-EventLog -LogName $EventLogName -Source $EventSource -EntryType $Level -EventId $Id -Message $Msg -ErrorAction Stop
  } catch {
    Write-UiStatus -Label "EventLog write" -State "WARN" -Detail $Msg
  }
}

function Ensure-Dir([string]$Path){
  if (-not $Path) { return }
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Save-Json([object]$Obj,[string]$Path){
  Ensure-Dir (Split-Path -Parent $Path)
  ($Obj | ConvertTo-Json -Depth 50) | Out-File -FilePath $Path -Encoding UTF8
}

function Expand-Env([string]$p){
  try { return [Environment]::ExpandEnvironmentVariables($p) } catch { return $p }
}

function Read-Json([string]$Path){
  try {
    if ($Path -and (Test-Path -LiteralPath $Path)) {
      return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -ErrorAction Stop
    }
  } catch { return $null }
  return $null
}

function Get-ObjPropValue {
  param(
    [Parameter(Mandatory=$true)] $Obj,
    [Parameter(Mandatory=$true)] [string] $Name
  )
  try {
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
  } catch { }
  return $null
}

function Get-OrDefault([object]$Value, [object]$Default){
  if ($null -ne $Value -and "$Value" -ne "") { return $Value }
  return $Default
}

function New-DefaultCatalog {
  $cat = New-Object psobject
  Add-Member -InputObject $cat -MemberType NoteProperty -Name Proof       -Value ([pscustomobject]@{ OutFile = $DefaultProofOutFile })
  Add-Member -InputObject $cat -MemberType NoteProperty -Name EvidenceDir -Value $DefaultEvidenceDir

  Add-Member -InputObject $cat -MemberType NoteProperty -Name Files          -Value @()
  Add-Member -InputObject $cat -MemberType NoteProperty -Name FileGlobs      -Value @()
  Add-Member -InputObject $cat -MemberType NoteProperty -Name Registry       -Value @()
  Add-Member -InputObject $cat -MemberType NoteProperty -Name Services       -Value @()
  Add-Member -InputObject $cat -MemberType NoteProperty -Name ScheduledTasks -Value @()
  Add-Member -InputObject $cat -MemberType NoteProperty -Name Processes      -Value @()
  Add-Member -InputObject $cat -MemberType NoteProperty -Name IPs            -Value @()
  Add-Member -InputObject $cat -MemberType NoteProperty -Name Domains        -Value @()

  return $cat
}

function Load-Catalog {
  param([string]$CatalogPath,[string]$ConfigPath)

  $res = [ordered]@{ Catalog = $null; Source = 'Default'; Errors = @() }

  if ($CatalogPath) {
    $c = Read-Json $CatalogPath
    if ($c) { $res.Catalog = $c; $res.Source = 'CatalogPath'; return $res }
    $res.Errors += ("CatalogPath not loaded: {0}" -f $CatalogPath)
  }

  $cfg = $null
  if ($ConfigPath) {
    $cfg = Read-Json $ConfigPath
    if (-not $cfg) { $res.Errors += ("ConfigPath not loaded: {0}" -f $ConfigPath) }
  }

  $p = $null
  try { if ($cfg -and $cfg.IOC -and $cfg.IOC.CatalogPath) { $p = [string]$cfg.IOC.CatalogPath } } catch { $p = $null }

  if ($p) {
    $c2 = Read-Json $p
    if ($c2) { $res.Catalog = $c2; $res.Source = 'Config->IOC.CatalogPath'; return $res }
    $res.Errors += ("Config IOC.CatalogPath not loaded: {0}" -f $p)
  }

  $res.Catalog = (New-DefaultCatalog)
  $res.Source  = 'Default'
  return $res
}

function Get-FilePublisher([string]$File){
  if (-not $File -or -not (Test-Path -LiteralPath $File)) { return $null, $false }
  try {
    $sig = Get-AuthenticodeSignature -FilePath $File -ErrorAction Stop
    return $sig.SignerCertificate.Subject, ($sig.Status -eq 'Valid')
  } catch {
    return $null, $false
  }
}

function Get-FileSha256([string]$File){
  try { return (Get-FileHash -Path $File -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return $null }
}

function Copy-ToEvidence([string]$Src,[string]$BaseDir){
  try {
    if (-not (Test-Path -LiteralPath $Src)) { return $false, "missing" }
    if (-not $BaseDir) { return $false, "no evidence dir" }

    $rel = $Src.Replace(':','').TrimStart('\') -replace '[\\/:*?"<>|]','_'
    $dst = Join-Path $BaseDir $rel
    Ensure-Dir (Split-Path -Parent $dst)
    Copy-Item -LiteralPath $Src -Destination $dst -Force -ErrorAction Stop
    return $true, $dst
  } catch {
    return $false, $_.Exception.Message
  }
}

function Convert-RegProviderToRegExePath([string]$KeyPath){
  if (-not $KeyPath) { return $null }
  $p = $KeyPath
  if ($p -like 'Registry::*') { $p = $p -replace '^Registry::','' }

  $p = $p.Replace('HKLM:\','HKEY_LOCAL_MACHINE\')
  $p = $p.Replace('HKCU:\','HKEY_CURRENT_USER\')
  $p = $p.Replace('HKCR:\','HKEY_CLASSES_ROOT\')
  $p = $p.Replace('HKU:\','HKEY_USERS\')
  $p = $p.Replace('HKCC:\','HKEY_CURRENT_CONFIG\')
  return $p
}

function Export-Reg([string]$RegPath,[string]$OutFile){
  try {
    Ensure-Dir (Split-Path -Parent $OutFile)
    & reg.exe export $RegPath $OutFile /y | Out-Null
    return $true, $OutFile
  } catch {
    return $false, $_.Exception.Message
  }
}

function Find-MpCmdRun {
  $cands = @(
    "$env:ProgramFiles\Windows Defender\MpCmdRun.exe",
    "$env:ProgramFiles\Microsoft Defender\MpCmdRun.exe"
  )
  foreach ($c in $cands) {
    if (Test-Path -LiteralPath $c) { return $c }
  }
  return $null
}

# -----------------------------
# Proof object (data only)
# -----------------------------
$Proof = [ordered]@{
  Time      = (Get-Date).ToString('s')
  Hostname  = $env:COMPUTERNAME
  User      = $env:USERNAME
  IsAdmin   = (Test-IsAdmin)
  Params    = @{
    CatalogPath      = (Get-OrDefault $CatalogPath "")
    ConfigPath       = (Get-OrDefault $ConfigPath "")
    Remediate        = [bool]$Remediate
    CollectEvidence  = [bool]$CollectEvidence
    ScanType         = $ScanType
    CustomScanPaths  = @($CustomScanPaths)
    Strict           = [bool]$Strict
    PassThru         = [bool]$PassThru
  }
  Catalog   = @{ Source = ""; Errors = @() }
  Scan      = @{}
  Findings  = @{
    Files     = @()
    Registry  = @()
    Services  = @()
    Tasks     = @()
    Processes = @()
    Network   = @()
  }
  Actions   = @()
  Errors    = @()
  Summary   = @{}
}

Ensure-EventSource

$ok       = $true
$foundAny = $false
$outFile  = $DefaultProofOutFile
$evDir    = $DefaultEvidenceDir
$cat      = $null

try {
  $catLoad = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath
  $cat = $catLoad.Catalog
  $Proof.Catalog.Source = $catLoad.Source
  $Proof.Catalog.Errors = @($catLoad.Errors)

  $proofObj = Get-ObjPropValue $cat 'Proof'
  if ($proofObj) { $outFile = Get-ObjPropValue $proofObj 'OutFile' }
  $outFile = [string](Get-OrDefault $outFile $DefaultProofOutFile)

  $evDir = Get-OrDefault (Get-ObjPropValue $cat 'EvidenceDir') $DefaultEvidenceDir
  $evDir = [string]$evDir

  if ($CollectEvidence) { Ensure-Dir $evDir }
  Ensure-Dir (Split-Path -Parent $outFile)

  # Defender scan
  try {
    $mp = Find-MpCmdRun
    $scanInfo = @{ Requested = $ScanType; Result = "skipped"; MpCmdRun = $mp }

    if ($mp) {
      if ($ScanType -eq 'None') {
        if ($CustomScanPaths -and $CustomScanPaths.Count -gt 0) {
          $expanded = @()
          foreach ($c in $CustomScanPaths) {
            $e = Expand-Env $c
            if ($e -and (Test-Path -LiteralPath $e)) { $expanded += $e }
          }

          if ($expanded.Count -gt 0) {
            $results = @()
            foreach ($item in $expanded) {
              $args = @("-Scan","-ScanType","3","-File",$item)
              $p = Start-Process -FilePath $mp -ArgumentList $args -PassThru -Wait -WindowStyle Hidden
              $results += ("custom:{0} exit:{1}" -f $item, $p.ExitCode)
            }
            $scanInfo.Result = ($results -join "; ")
          } else {
            $scanInfo.Result = "skipped(no valid CustomScanPaths)"
          }
        }
      } else {
        $type = 2
        if ($ScanType -eq 'Quick') { $type = 1 }
        $args = @("-Scan","-ScanType", "$type")
        $p = Start-Process -FilePath $mp -ArgumentList $args -PassThru -Wait -WindowStyle Hidden
        $scanInfo.Result = "exit:$($p.ExitCode)"
      }
    }

    $Proof.Scan = $scanInfo
  } catch {
    $Proof.Errors += "Defender scan failed: $($_.Exception.Message)"
    $ok = $false
  }

  # File IOCs
  foreach ($f in @($cat.Files)) {
    $pathVal = Get-ObjPropValue $f 'Path'
    $p = Expand-Env ([string]$pathVal)
    if (-not $p) { continue }
    if (-not (Test-Path -LiteralPath $p)) { continue }

    $sha = Get-FileSha256 $p
    $pub,$valid = Get-FilePublisher $p

    $fSha    = [string](Get-ObjPropValue $f 'Sha256')
    $fSigner = [string](Get-ObjPropValue $f 'Signer')

    $matchSha = ($fSha -and $sha -and ($sha -ieq $fSha))
    $matchSig = ($fSigner -and $pub -and ($pub -like ("*{0}*" -f $fSigner)))

    $hit = $false
    if ($fSha) { $hit = $matchSha }
    elseif ($fSigner) { $hit = $matchSig }
    else { $hit = $false }

    if ($hit) {
      $foundAny = $true
      $evPath = $null
      if ($CollectEvidence) {
        $okc,$ev = Copy-ToEvidence -Src $p -BaseDir $evDir
        if ($okc) { $evPath = $ev } else { $Proof.Errors += "Evidence copy failed ($p): $ev"; $ok = $false }
      }

      $Proof.Findings.Files += [ordered]@{
        Kind      = 'File'
        Path      = $p
        Sha256    = $sha
        Publisher = $pub
        Signed    = $valid
        Evidence  = $evPath
        Action    = (Get-ObjPropValue $f 'Action')
        Match     = [ordered]@{ Sha256 = $matchSha; Signer = $matchSig }
      }
    }
  }

  foreach ($g in @($cat.FileGlobs)) {
    $globVal = Get-ObjPropValue $g 'Glob'
    $glob    = Expand-Env ([string]$globVal)
    if (-not $glob) { continue }

    $dir = Split-Path $glob -Parent
    $pat = Split-Path $glob -Leaf
    if (-not (Test-Path -LiteralPath $dir)) { continue }

    $hits = Get-ChildItem -LiteralPath $dir -Filter $pat -File -ErrorAction SilentlyContinue
    foreach ($h in $hits) {
      $sha = Get-FileSha256 $h.FullName
      $pub,$valid = Get-FilePublisher $h.FullName

      $gSha    = [string](Get-ObjPropValue $g 'Sha256')
      $gSigner = [string](Get-ObjPropValue $g 'Signer')

      if ($gSha -and $sha -and ($sha -ine $gSha)) { continue }
      if ($gSigner -and $pub -and ($pub -notlike ("*{0}*" -f $gSigner))) { continue }
      if (-not $gSha -and -not $gSigner) { continue }

      $foundAny = $true
      $evPath = $null
      if ($CollectEvidence) {
        $okc,$ev = Copy-ToEvidence -Src $h.FullName -BaseDir $evDir
        if ($okc) { $evPath = $ev } else { $Proof.Errors += "Evidence copy failed ($($h.FullName)): $ev"; $ok = $false }
      }

      $Proof.Findings.Files += [ordered]@{
        Kind      = 'Glob'
        Path      = $h.FullName
        Sha256    = $sha
        Publisher = $pub
        Signed    = $valid
        Evidence  = $evPath
        Action    = (Get-ObjPropValue $g 'Action')
      }
    }
  }

  # Registry IOCs
  foreach ($r in @($cat.Registry)) {
    $path = [string](Get-ObjPropValue $r 'Path')
    if (-not $path) { continue }

    $okReg = $false
    $data  = $null
    $key   = $null
    $value = $null

    try {
      $key   = Split-Path $path -Parent
      $value = Split-Path $path -Leaf
      $prop  = Get-ItemProperty -Path $key -ErrorAction Stop
      if ($prop.PSObject.Properties.Name -contains $value) {
        $data  = $prop.$value
        $okReg = $true
      }
    } catch { $okReg = $false }

    if ($okReg) {
      $regexOk = $true
      $dr = [string](Get-ObjPropValue $r 'DataRegex')
      if ($dr) { $regexOk = ($data -match $dr) }

      if ($regexOk) {
        $foundAny = $true
        $regExp = $null

        if ($CollectEvidence) {
          $regExePath = Convert-RegProviderToRegExePath $key
          $safeKey    = ($key -replace '[:\\]','_')
          $out        = Join-Path $evDir ("reg-{0}.reg" -f $safeKey)
          $okx,$exportOut = Export-Reg -RegPath $regExePath -OutFile $out
          if ($okx) { $regExp = $exportOut } else { $Proof.Errors += "Reg export failed ($key): $exportOut"; $ok = $false }
        }

        $Proof.Findings.Registry += [ordered]@{
          Path     = $path
          Data     = $data
          Evidence = $regExp
          Action   = (Get-ObjPropValue $r 'Action')
        }

        if ($Remediate -and ((Get-ObjPropValue $r 'Action') -eq 'neutralize')) {
          try {
            Remove-ItemProperty -Path $key -Name $value -Force -ErrorAction Stop
            $Proof.Actions += "Registry neutralized: $path"
          } catch {
            $Proof.Errors += "Registry neutralize failed ($path): $($_.Exception.Message)"
            $ok = $false
          }
        }
      }
    }
  }

  # Services
  foreach ($s in @($cat.Services)) {
    $name = [string](Get-ObjPropValue $s 'Name')
    if (-not $name) { continue }

    try {
      $svc = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $name) -ErrorAction Stop
      $img = $svc.PathName

      $match = $true
      $imgRx = [string](Get-ObjPropValue $s 'ImagePathRegex')
      if ($imgRx) { if ($img -notmatch $imgRx) { $match = $false } }

      if ($match) {
        $foundAny = $true
        $action = [string](Get-ObjPropValue $s 'Action')

        $Proof.Findings.Services += [ordered]@{
          Name        = $svc.Name
          DisplayName = $svc.DisplayName
          State       = $svc.State
          StartMode   = $svc.StartMode
          ImagePath   = $img
          Action      = $action
        }

        if ($Remediate -and ($action -in @('disable','stop'))) {
          try {
            if ($svc.State -ne 'Stopped') { Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue }
            if ($action -eq 'disable')    { Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue }
            $Proof.Actions += "Service remediated: $($svc.Name) ($action)"
          } catch {
            $Proof.Errors += "Service remediation failed ($($svc.Name)): $($_.Exception.Message)"
            $ok = $false
          }
        }
      }
    } catch { }
  }

  # Scheduled tasks
  $allTasks = @()
  try { $allTasks = Get-ScheduledTask -ErrorAction Stop } catch { $allTasks = @() }

  foreach ($t in @($cat.ScheduledTasks)) {
    $rx = [string](Get-ObjPropValue $t 'Regex')
    if (-not $rx) { continue }

    foreach ($task in $allTasks) {
      $full = $task.TaskPath + $task.TaskName
      if ($full -match $rx) {
        $foundAny = $true

        $state = "Unknown"
        try {
          $ti = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
          if ($ti -and $ti.State) { $state = $ti.State.ToString() }
        } catch { $state = "Unknown" }

        $action = [string](Get-ObjPropValue $t 'Action')

        $Proof.Findings.Tasks += [ordered]@{
          Path    = $full
          Enabled = [bool]$task.Enabled
          State   = $state
          Action  = $action
        }

        if ($Remediate -and ($action -eq 'disable')) {
          try {
            Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue | Out-Null
            $Proof.Actions += "Task disabled: $full"
          } catch {
            $Proof.Errors += "Task disable failed ($full): $($_.Exception.Message)"
            $ok = $false
          }
        }
      }
    }
  }

  # Processes
  $procs = Get-Process -ErrorAction SilentlyContinue
  foreach ($pRule in @($cat.Processes)) {
    $imgRx = [string](Get-ObjPropValue $pRule 'ImageRegex')
    if (-not $imgRx) { continue }

    foreach ($pr in $procs) {
      $img = $null
      try { $img = $pr.Path } catch { $img = $null }
      if (-not $img) { continue }

      if ($img -match $imgRx) {
        $pub,$valid = Get-FilePublisher $img
        $signer = [string](Get-ObjPropValue $pRule 'Signer')
        if ($signer -and $pub -and ($pub -notlike ("*{0}*" -f $signer))) { continue }

        $foundAny = $true
        $Proof.Findings.Processes += [ordered]@{
          Name      = $pr.Name
          Id        = $pr.Id
          Path      = $img
          Publisher = $pub
          Signed    = $valid
          Action    = (Get-ObjPropValue $pRule 'Action')
        }
      }
    }
  }

  # Network (IPs + DNS cache)
  $nFind = @()

  try {
    $ips = @($cat.IPs)
    if ($ips.Count -gt 0) {
      $conns = Get-NetTCPConnection -State Established,SynSent,SynReceived -ErrorAction SilentlyContinue
      foreach ($c in $conns) {
        if ($ips -contains $c.RemoteAddress) {
          $foundAny = $true

          $pName = $null
          try { $pName = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).Name } catch { $pName = $null }

          $nFind += [ordered]@{
            Kind          = 'IP'
            Remote        = $c.RemoteAddress
            Local         = $c.LocalAddress
            LPort         = $c.LocalPort
            RPort         = $c.RemotePort
            State         = $c.State
            OwningProcess = $c.OwningProcess
            ProcessName   = $pName
          }
        }
      }
    }

    $domains = @($cat.Domains)
    if ($domains.Count -gt 0) {
      try {
        $dns = Get-DnsClientCache -ErrorAction Stop
        foreach ($d in $domains) {
          foreach ($h in $dns) {
            $entry = Get-ObjPropValue $h 'Entry'
            if (-not $entry) { $entry = Get-ObjPropValue $h 'Name' }
            if (-not $entry) { $entry = Get-ObjPropValue $h 'RecordName' }

            if ($entry -and ([string]$entry -ieq [string]$d)) {
              $foundAny = $true
              $typ = Get-ObjPropValue $h 'Type'
              if (-not $typ) { $typ = Get-ObjPropValue $h 'RecordType' }
              $dat = Get-ObjPropValue $h 'Data'

              $nFind += [ordered]@{
                Kind  = 'Domain'
                Entry = $entry
                Type  = $typ
                Data  = $dat
              }
            }
          }
        }
      } catch { }
    }
  } catch { }

  if ($nFind.Count -gt 0) { $Proof.Findings.Network = $nFind }

  Save-Json -Obj $Proof -Path $outFile

  if ($foundAny -or (@($Proof.Errors).Count -gt 0) -or $Strict) {
    $msg = "IOC sweep: findings/errors detected. Proof: $outFile"
    if (@($Proof.Errors).Count -gt 0) { $msg += " | Errors: " + ($Proof.Errors -join ' | ') }
    Write-HealthEvent -Id 10010 -Msg $msg -Level 'Warning'
  } else {
    Write-HealthEvent -Id 10000 -Msg ("IOC sweep: OK (no findings). Proof: $outFile") -Level 'Information'
  }

} catch {
  $ok = $false
  $err = "IOC sweep failed: $($_.Exception.Message)"
  $Proof.Errors += $err

  try { Save-Json -Obj $Proof -Path $outFile } catch { }
  Write-HealthEvent -Id 10010 -Msg $err -Level 'Error'
}

# -----------------------------
# Summary (data + pretty host output)
# -----------------------------
$filesCount = @($Proof.Findings.Files).Count
$regCount   = @($Proof.Findings.Registry).Count
$svcCount   = @($Proof.Findings.Services).Count
$taskCount  = @($Proof.Findings.Tasks).Count
$procCount  = @($Proof.Findings.Processes).Count
$netCount   = @($Proof.Findings.Network).Count
$actCount   = @($Proof.Actions).Count
$errCount   = @($Proof.Errors).Count
$totalFindings = $filesCount + $regCount + $svcCount + $taskCount + $procCount + $netCount

$exitCode = 0
if (-not ($ok -and -not $foundAny -and ($errCount -eq 0))) { $exitCode = 1 }

$Proof.Summary = @{
  CatalogSource  = $Proof.Catalog.Source
  FindingsTotal  = $totalFindings
  Files          = $filesCount
  Registry       = $regCount
  Services       = $svcCount
  Tasks          = $taskCount
  Processes      = $procCount
  Network        = $netCount
  Actions        = $actCount
  Errors         = $errCount
  ExitCode       = $exitCode
  ProofFile      = $outFile
  EvidenceDir    = $evDir
}

# Pretty output
Write-UiHeader "IOC Sweep (Defender) - Result"
Write-UiKV "Time"     $Proof.Time     Gray
Write-UiKV "Host"     $Proof.Hostname Gray
Write-UiKV "User"     $Proof.User     Gray

$adminColor = [ConsoleColor]::Yellow
if ($Proof.IsAdmin) { $adminColor = [ConsoleColor]::Green }
Write-UiKV "Admin" ([string]$Proof.IsAdmin) $adminColor

$catColor = [ConsoleColor]::Green
if ($Proof.Catalog.Source -eq 'Default') { $catColor = [ConsoleColor]::Yellow }
Write-UiKV "Catalog" $Proof.Catalog.Source $catColor

if (@($Proof.Catalog.Errors).Count -gt 0) {
  Write-UiStatus -Label "Catalog warnings" -State "WARN" -Detail ("{0} issue(s)" -f @($Proof.Catalog.Errors).Count)
  foreach ($ce in $Proof.Catalog.Errors) { Write-UiBullet $ce DarkGray }
} else {
  Write-UiStatus -Label "Catalog load" -State "OK" -Detail "No issues"
}

$scanReq = Get-OrDefault $Proof.Scan.Requested "n/a"
$scanRes = Get-OrDefault $Proof.Scan.Result "n/a"
Write-UiKV "Scan" ("{0} -> {1}" -f $scanReq, $scanRes) Cyan
Write-UiKV "Proof" $outFile Gray
Write-UiKV "Evidence" $evDir Gray

Write-Host ""
if ($exitCode -eq 0) {
  Write-UiStatus -Label "Overall status" -State "OK" -Detail "No findings and no errors"
} elseif ($errCount -gt 0) {
  Write-UiStatus -Label "Overall status" -State "FAIL" -Detail "Errors occurred (check proof file)"
} else {
  Write-UiStatus -Label "Overall status" -State "WARN" -Detail "Findings detected (check proof file)"
}

Write-Host ""
Write-UiLine "Findings breakdown:" DarkGray

$fc = [ConsoleColor]::Green; if ($filesCount -gt 0) { $fc = [ConsoleColor]::Yellow }
$rc = [ConsoleColor]::Green; if ($regCount -gt 0)   { $rc = [ConsoleColor]::Yellow }
$sc = [ConsoleColor]::Green; if ($svcCount -gt 0)   { $sc = [ConsoleColor]::Yellow }
$tc = [ConsoleColor]::Green; if ($taskCount -gt 0)  { $tc = [ConsoleColor]::Yellow }
$pc = [ConsoleColor]::Green; if ($procCount -gt 0)  { $pc = [ConsoleColor]::Yellow }
$nc = [ConsoleColor]::Green; if ($netCount -gt 0)   { $nc = [ConsoleColor]::Yellow }

Write-UiBullet ("Files:     {0}" -f $filesCount) $fc
Write-UiBullet ("Registry:  {0}" -f $regCount)   $rc
Write-UiBullet ("Services:  {0}" -f $svcCount)   $sc
Write-UiBullet ("Tasks:     {0}" -f $taskCount)  $tc
Write-UiBullet ("Processes: {0}" -f $procCount)  $pc
Write-UiBullet ("Network:   {0}" -f $netCount)   $nc

Write-Host ""
$actColor = [ConsoleColor]::Green; if ($actCount -gt 0) { $actColor = [ConsoleColor]::Yellow }
$errColor = [ConsoleColor]::Green; if ($errCount -gt 0) { $errColor = [ConsoleColor]::Red }
$exitColor = [ConsoleColor]::Green; if ($exitCode -ne 0) { $exitColor = [ConsoleColor]::Yellow }

Write-UiKV "Actions"  ([string]$actCount) $actColor
Write-UiKV "Errors"   ([string]$errCount) $errColor
Write-UiKV "ExitCode" ([string]$exitCode) $exitColor

if ($errCount -gt 0) {
  Write-Host ""
  Write-UiStatus -Label "Error details" -State "FAIL"
  foreach ($e in $Proof.Errors) { Write-UiBullet $e Red }
}

# Pipeline output only when explicitly requested
if ($PassThru) { $Proof }

exit $exitCode
