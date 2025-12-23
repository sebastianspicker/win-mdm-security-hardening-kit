<#
.SYNOPSIS
  Collects endpoint artifacts and packages them into a structured incident-response bundle.

.DESCRIPTION
  This script gathers common forensic/IR artifacts from a Windows endpoint and writes them to a timestamped working
  directory, a JSON summary, and a ZIP bundle.

  Collection is normally gated by a trigger (registry value and/or file flag). Use -Force to run immediately.

  The script is designed for two consumers at once:
  - Humans: a “pretty” console summary at the end (with colored highlights and optional Top-N suspicious items).
  - Automation: structured outputs (CSV and JSON) that remain pipeline-friendly and easy to parse.

  Artifacts collected (high level):
  - Processes: PID, name, command line, executable path; optional SHA256 hashing; optional Authenticode info.
  - Network: TCP connections, listeners, UDP endpoints (best-effort), routing, IP configuration, DNS cache (best-effort).
  - Scheduled Tasks: flattened CSV; optional XML export for suspicious tasks.
  - WMI persistence: event filters, bindings, and multiple consumer types.
  - Autoruns: Run/RunOnce keys for HKLM and HKCU.
  - Samples (optional): copies selected executables into an evidence folder (size-limited and policy-controlled).

.PARAMETER CatalogPath
  Optional path to a JSON “catalog” that defines output base path, trigger locations, and collection policies.

  If provided and readable, it overrides the built-in defaults. If missing/unreadable, the script continues with
  safe defaults.

.PARAMETER ConfigPath
  Optional path to a JSON config file that can point to a catalog (for example, via a property like Grabber.CatalogPath).

  If CatalogPath is not specified or cannot be loaded, the script attempts to load a catalog via ConfigPath.
  If that also fails, built-in defaults are used.

.PARAMETER Force
  Runs the script immediately, even if no registry/file trigger is present.

  Use this for manual/interactive runs or when a trigger mechanism is not deployed.

.PARAMETER CollectSamples
  Forces sample collection (copying files into the evidence folder) subject to the configured size limits
  and filtering rules.

  This is additive: it enables samples even if the trigger did not request samples.

.PARAMETER HashAllProcesses
  Hashes all process executable paths (when readable), not only “userland” paths.

  Note: hashing all processes increases runtime and I/O.

.PARAMETER Strict
  Makes the run more “fail loud” from an operational perspective by treating findings/errors as warnings for status/logging.
  Data collection still follows best-effort behavior where applicable.

.INPUTS
  None. This script does not accept pipeline input.

.OUTPUTS
  This script writes files to disk and prints a human-readable summary to the host.

  Primary on-disk outputs (within the working directory):
  - Summary.json
    A structured summary object containing run metadata, counts, findings, errors/notes (if any), and optional Top-N items.
  - CSV files per collector (for example processes.csv, tasks.csv, network CSVs, autoruns CSVs, WMI CSVs).
  - Optional XML exports for suspicious scheduled tasks.
  - Optional evidence copies under a samples/ folder (policy-controlled).

  Final bundle:
  - A ZIP archive containing the full working directory content.

  Pipeline output:
  - None by default (intentionally). All “pretty” formatting is done via host output to keep pipelines clean.

.EXAMPLE
  # Run using deployed triggers (registry/file flag)
  .\IR-Grabber.ps1

.EXAMPLE
  # Force a run (ignores triggers)
  .\IR-Grabber.ps1 -Force

.EXAMPLE
  # Force a run and enable sample collection
  .\IR-Grabber.ps1 -Force -CollectSamples

.EXAMPLE
  # Load a specific catalog JSON
  .\IR-Grabber.ps1 -CatalogPath "PATH/TO/JSON/catalog.json" -Force

.EXAMPLE
  # Hash all process images (more I/O)
  .\IR-Grabber.ps1 -Force -HashAllProcesses

.EXAMPLE
  # Automated usage: run and then consume the generated summary
  .\IR-Grabber.ps1 -Force
  Get-Content -Raw "PATH/TO/OUTPUT/ir/H2/<timestamp>/Summary.json" | ConvertFrom-Json

.NOTES
  Operational guidance:
  - Run from an elevated console if you expect restricted artifacts (some registry areas, task exports, event source creation)
    to be accessible.
  - Sample collection is intentionally constrained by size limits and filtering rules to reduce risk and volume.
  - Network and DNS cache collection are best-effort; availability varies by OS features and permissions.

  Using Get-Help:
  - Get full help:    Get-Help .\IR-Grabber.ps1 -Full
  - View examples:   Get-Help .\IR-Grabber.ps1 -Examples
#>


[CmdletBinding()]
param(
  [string]$CatalogPath,
  [switch]$Force,
  [switch]$CollectSamples,
  [switch]$HashAllProcesses,
  [switch]$Strict,
  [string]$ConfigPath = "PATH/TO/JSON/config.json"
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Make Write-Information visible for humans; it is controlled by InformationPreference. 
$InformationPreference = 'Continue'

# -------------------------
# Globals
# -------------------------
$EventSource   = 'IR-Grabber'
$ScriptVersion = '2025.12.22-ps51'

# -------------------------
# Console helpers (no pipeline output)
# -------------------------
function Write-UiLine {
  param(
    [int]$Width = 78,
    [ConsoleColor]$Color = 'DarkGray'
  )
  Write-Host (''.PadLeft($Width,'-')) -ForegroundColor $Color
}

function Write-UiHeader {
  param(
    [string]$Title,
    [string]$Subtitle
  )
  Write-UiLine
  Write-Host $Title -ForegroundColor Cyan
  if ($Subtitle) { Write-Host $Subtitle -ForegroundColor DarkCyan }
  Write-UiLine
}

function Write-UiKeyValue {
  param(
    [string]$Key,
    [string]$Value,
    [ConsoleColor]$KeyColor = 'Gray',
    [ConsoleColor]$ValueColor = 'White'
  )
  Write-Host ("{0,-12}: " -f $Key) -ForegroundColor $KeyColor -NoNewline
  Write-Host ($Value) -ForegroundColor $ValueColor
}

function Write-UiStatus {
  param(
    [string]$Label,
    [ValidateSet('OK','WARN','FAIL','INFO')]
    [string]$State,
    [string]$Text
  )

  $c = 'Gray'
  switch ($State) {
    'OK'   { $c = 'Green' }
    'WARN' { $c = 'Yellow' }
    'FAIL' { $c = 'Red' }
    'INFO' { $c = 'Cyan' }
  }

  Write-Host ("[{0}] " -f $State) -ForegroundColor $c -NoNewline
  if ($Label) { Write-Host ("{0}: " -f $Label) -ForegroundColor Gray -NoNewline }
  if ($Text) { Write-Host $Text -ForegroundColor White } else { Write-Host "" }
}

# -------------------------
# Logging helpers
# -------------------------
function Ensure-EventSource {
  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
      New-EventLog -LogName Application -Source $EventSource -ErrorAction Stop | Out-Null
    }
  } catch {
    # best-effort
  }
}

function Write-HealthEvent {
  param(
    [int]$Id,
    [string]$Msg,
    [ValidateSet('Information','Warning','Error')]
    [string]$Level = 'Information'
  )
  try {
    Write-EventLog -LogName Application -Source $EventSource -EntryType $Level -EventId $Id -Message $Msg
  } catch {
    Write-Host ("[{0}][{1}] {2}" -f $Level,$Id,$Msg) -ForegroundColor DarkGray
  }
}

# -------------------------
# Generic helpers
# -------------------------
function Ensure-Dir([string]$Path) {
  if (-not $Path) { return }
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Expand-Env([string]$p) {
  try { [Environment]::ExpandEnvironmentVariables($p) } catch { $p }
}

function Save-Json([object]$Obj,[string]$Path) {
  Ensure-Dir (Split-Path -Parent $Path)
  ($Obj | ConvertTo-Json -Depth 30) | Out-File -FilePath $Path -Encoding UTF8
}

function Read-Json([string]$Path) {
  try {
    if ($Path -and (Test-Path -LiteralPath $Path)) {
      return (Get-Content -Raw -Path $Path -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
    }
  } catch { }
  return $null
}

function New-ResultObject([string]$Name) {
  [pscustomobject]@{
    Name   = $Name
    Counts = @{}
    Errors = (New-Object System.Collections.Generic.List[string])
    Notes  = (New-Object System.Collections.Generic.List[string])
  }
}

function Add-Error([object]$res,[string]$msg) { if ($msg) { [void]$res.Errors.Add($msg) } }
function Add-Note ([object]$res,[string]$msg) { if ($msg) { [void]$res.Notes.Add($msg) } }

function Safe-ToInt {
  param([object]$Value,[int]$Default = 0)
  try {
    if ($null -eq $Value) { return $Default }
    return [int]$Value
  } catch { return $Default }
}

function Safe-ToBool {
  param([object]$Value,[bool]$Default = $false)
  try {
    if ($null -eq $Value) { return $Default }
    return [bool]$Value
  } catch { return $Default }
}

function Get-FileSha256([string]$File) {
  try { (Get-FileHash -Algorithm SHA256 -Path $File -ErrorAction Stop).Hash } catch { $null }
}

function Get-FileSignatureInfo([string]$File) {
  $o = [pscustomobject]@{
    Path            = $File
    SignatureStatus = $null
    Signed          = $false
    Publisher       = $null
  }
  try {
    if (-not (Test-Path -LiteralPath $File)) { return $o }
    $sig = Get-AuthenticodeSignature -FilePath $File -ErrorAction Stop
    $o.SignatureStatus = [string]$sig.Status
    $o.Signed = ($sig.Status -eq 'Valid')
    if ($sig.SignerCertificate) { $o.Publisher = $sig.SignerCertificate.Subject }
  } catch { }
  return $o
}

function Copy-ToEvidence {
  param(
    [string]$Src,
    [string]$BaseDir,
    [int]$MaxFileSizeMB,
    [int]$MaxTotalMB,
    [ref]$runningTotalBytes
  )
  try {
    if (-not (Test-Path -LiteralPath $Src)) { return $false, "missing" }
    $fi = Get-Item -LiteralPath $Src -ErrorAction Stop
    if ($fi.PSIsContainer) { return $false, "is-directory" }

    $sizeBytes    = [int64]$fi.Length
    $maxFileBytes = [int64]$MaxFileSizeMB * 1MB
    $maxTotBytes  = [int64]$MaxTotalMB * 1MB

    if ($sizeBytes -gt $maxFileBytes) { return $false, "too-large-file" }
    if ($runningTotalBytes.Value + $sizeBytes -gt $maxTotBytes) { return $false, "total-limit" }

    $rel = $Src.Replace(':','').TrimStart('\') -replace '[\\/:*?"<>|]','_'
    $dst = Join-Path $BaseDir $rel
    Ensure-Dir (Split-Path -Parent $dst)

    Copy-Item -LiteralPath $Src -Destination $dst -Force -ErrorAction Stop
    $runningTotalBytes.Value += $sizeBytes
    return $true, $dst
  } catch {
    return $false, $_.Exception.Message
  }
}

function Get-PSObjectPropertyValue {
  param([object]$Obj,[string]$Name)
  try {
    if ($null -eq $Obj) { return $null }
    if ($Obj.PSObject.Properties.Name -contains $Name) { return $Obj.$Name }
  } catch { }
  return $null
}

function New-RunId {
  (Get-Date).ToString('yyyyMMdd-HHmmss')
}

function New-BaseClone {
  param([object]$Obj)
  # JSON roundtrip clone to avoid accidental cross-run mutation
  return ($Obj | ConvertTo-Json -Depth 30 | ConvertFrom-Json)
}

# -------------------------
# Defaults (used when JSON is missing/unreadable)
# -------------------------
$DefaultCatalog = [pscustomobject]@{
  OutputBase = "PATH/TO/OUTPUT/ir/H2"
  Trigger    = [pscustomobject]@{
    Registry = 'HKLM:\SOFTWARE\IR\Grabber'
    FileFlag = 'PATH/TO/FLAG/GRAB.txt'
  }
  Process    = [pscustomobject]@{
    HashUserlandOnly = $true
    UserPathsRegex   = @(
      '^C:\\Users\\[^\\]+\\AppData\\',
      '^C:\\ProgramData\\',
      '^C:\\Windows\\Temp\\'
    )
  }
  Samples    = [pscustomobject]@{
    Enable                = $false
    MaxFileSizeMB         = 20
    MaxTotalMB            = 100
    OnlyUnsignedOrUnknown = $true
    PathIncludeRegex      = @(
      '^C:\\Users\\[^\\]+\\AppData\\',
      '^C:\\ProgramData\\'
    )
  }
  Tasks      = [pscustomobject]@{
    ExportXmlForSuspicious = $true
    SuspiciousRegex        = @(
      '(?i)\\Users\\[^\\]+\\AppData\\',
      '(?i)\\Temp\\',
      '(?i)\\ProgramData\\'
    )
    MaxXml                = 50
  }
}

function Merge-Catalog {
  param($base,$override)

  if ($null -eq $override) { return $base }

  foreach ($section in @('OutputBase','Trigger','Process','Samples','Tasks')) {
    if ($section -eq 'OutputBase') {
      $v = Get-PSObjectPropertyValue -Obj $override -Name 'OutputBase'
      if ($v) { $base.OutputBase = [string]$v }
      continue
    }

    $ov = Get-PSObjectPropertyValue -Obj $override -Name $section
    if ($null -eq $ov) { continue }

    foreach ($p in $base.$section.PSObject.Properties.Name) {
      $v = Get-PSObjectPropertyValue -Obj $ov -Name $p
      if ($null -ne $v -and $v -ne '') { $base.$section.$p = $v }
    }

    foreach ($p in $ov.PSObject.Properties.Name) {
      if (-not ($base.$section.PSObject.Properties.Name -contains $p)) {
        try { $base.$section | Add-Member -NotePropertyName $p -NotePropertyValue $ov.$p -Force } catch { }
      }
    }
  }

  return $base
}

function Load-Catalog {
  param([string]$CatalogPath,[string]$ConfigPath,[ref]$CatalogLoadNote)

  $CatalogLoadNote.Value = $null
  $cat = $null

  if ($CatalogPath) {
    $cat = Read-Json $CatalogPath
    if ($cat) { $CatalogLoadNote.Value = "Catalog loaded from -CatalogPath" }
  }

  if ($null -eq $cat -and $ConfigPath) {
    $cfg = Read-Json $ConfigPath
    $p = $null
    try { $p = $cfg.Grabber.CatalogPath } catch { $p = $null }
    if ($p) {
      $cat = Read-Json ([string]$p)
      if ($cat) { $CatalogLoadNote.Value = "Catalog loaded from ConfigPath reference" }
    }
  }

  if ($null -eq $cat) { $CatalogLoadNote.Value = "Using defaults (no JSON or unreadable JSON)" }

  $baseClone = New-BaseClone $DefaultCatalog
  return (Merge-Catalog -base $baseClone -override $cat)
}

function Read-Trigger {
  param($cat,[switch]$Force,[switch]$CollectSamples)

  $reason   = $null
  $want     = $false
  $samples  = $false

  $maxFileMB  = Safe-ToInt $cat.Samples.MaxFileSizeMB 20
  $maxTotalMB = Safe-ToInt $cat.Samples.MaxTotalMB 100

  if ($Force) { $want = $true }

  try {
    $k = [string]$cat.Trigger.Registry
    $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    if ($p) {
      if ($p.Request -eq 1) { $want = $true }
      if ($p.IncludeSamples -eq 1) { $samples = $true }
      if ($p.PSObject.Properties.Name -contains 'Reason') { $reason = [string]$p.Reason }
      if ($p.PSObject.Properties.Name -contains 'MaxFileSizeMB') { $maxFileMB = Safe-ToInt $p.MaxFileSizeMB $maxFileMB }
      if ($p.PSObject.Properties.Name -contains 'MaxTotalMB') { $maxTotalMB = Safe-ToInt $p.MaxTotalMB $maxTotalMB }
    }
  } catch { }

  try {
    $ff = Expand-Env ([string]$cat.Trigger.FileFlag)
    if ($ff -and (Test-Path -LiteralPath $ff)) { $want = $true }
  } catch { }

  if ($CollectSamples) { $samples = $true }

  [pscustomobject]@{
    Want       = $want
    Reason     = $reason
    Samples    = $samples
    MaxFileMB  = $maxFileMB
    MaxTotalMB = $maxTotalMB
  }
}

# -------------------------
# Collectors
# -------------------------
function Collect-Processes {
  param([string]$outDir,$cat,[switch]$hashAll)

  $res = New-ResultObject 'Processes'
  $csv = Join-Path $outDir 'processes.csv'

  try {
    Ensure-Dir $outDir

    $rxList=@(); try { $rxList=@($cat.Process.UserPathsRegex) } catch { }
    $hashUserlandOnly = Safe-ToBool $cat.Process.HashUserlandOnly $true

    $procs = Get-CimInstance Win32_Process
    $rows = foreach ($p in $procs) {
      $path=$null; try { $path=[string]$p.ExecutablePath } catch { }

      $userlandMatch=$false
      if ($path) { foreach ($rx in $rxList) { if ($path -match $rx) { $userlandMatch=$true; break } } }

      $doHash=$false
      if ($hashAll) { $doHash=$true }
      elseif (-not $hashUserlandOnly) { $doHash=$true }
      elseif ($userlandMatch) { $doHash=$true }

      $sha=$null
      $sig=[pscustomobject]@{ Signed=$false; Publisher=$null; SignatureStatus=$null }
      if ($path) {
        if ($doHash) { $sha = Get-FileSha256 $path }
        $sig = Get-FileSignatureInfo $path
      }

      [pscustomobject]@{
        ProcessId    = $p.ProcessId
        Name         = $p.Name
        CommandLine  = $p.CommandLine
        Path         = $path
        UserlandPath = $userlandMatch
        Sha256       = $sha
        Signed       = [string]$sig.Signed
        Publisher    = $sig.Publisher
        SigStatus    = $sig.SignatureStatus
      }
    }

    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv
    $res.Counts.Count = @($rows).Count
  } catch {
    Add-Error $res ("process: " + $_.Exception.Message)
    $res.Counts.Count = 0
  }

  return $res
}

function Try-CollectNetworkNetCmdlets {
  param([string]$outDir,[ref]$counts,[ref]$note)

  $note.Value = $null
  try {
    $tcp = Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess
    $tcp | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_tcp.csv')

    $listen = $tcp | Where-Object { $_.State -eq 'Listen' }
    $listen | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_tcp_listen.csv')

    $counts.Value.Tcp = @($tcp).Count
    $counts.Value.Listeners = @($listen).Count

    try {
      $udp = Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess
      $udp | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_udp.csv')
      $counts.Value.Udp = @($udp).Count
    } catch {
      $counts.Value.Udp = 0
      $note.Value = "UDP cmdlet unavailable: " + $_.Exception.Message
    }

    try { Get-NetIPConfiguration | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_ipconfig.csv') } catch { }
    try {
      Get-NetRoute | Select-Object ifIndex,DestinationPrefix,NextHop,RouteMetric,PolicyStore |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_routes.csv')
    } catch { }
    try { Get-DnsClientCache | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'dns_cache.csv') } catch { }

    return $true
  } catch {
    $note.Value = "NetTCPConnection unavailable: " + $_.Exception.Message
    return $false
  }
}

function Collect-NetworkNetstatFallback {
  param([string]$outDir,[ref]$counts,[ref]$note)

  $note.Value = "Using netstat fallback"
  $counts.Value.Tcp = 0
  $counts.Value.Listeners = 0
  $counts.Value.Udp = 0

  try {
    $raw = & netstat.exe -ano 2>$null
    $rows = foreach ($line in @($raw)) {
      $t = ($line -as [string]).Trim()
      if (-not $t) { continue }
      if ($t -match '^(TCP|UDP)\s+') {
        $parts = $t -split '\s+'
        if ($parts.Count -lt 4) { continue }

        $proto = $parts[0]
        $local = $parts[1]
        $remote = $parts[2]

        $state = $null
        $pid = $null

        if ($proto -eq 'TCP') {
          if ($parts.Count -ge 5) {
            $state = $parts[3]
            $pid = $parts[4]
          }
        } else {
          $pid = $parts[3]
        }

        $la=$null;$lp=$null;$ra=$null;$rp=$null

        if ($local -match '^(.*):(\d+)$') { $la=$matches[1]; $lp=[int]$matches[2] } else { $la=$local }
        if ($remote -match '^(.*):(\d+)$') { $ra=$matches[1]; $rp=[int]$matches[2] } else { $ra=$remote }

        [pscustomobject]@{
          Protocol      = $proto
          LocalAddress  = $la
          LocalPort     = $lp
          RemoteAddress = $ra
          RemotePort    = $rp
          State         = $state
          OwningProcess = $pid
        }
      }
    }

    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_netstat_ano.csv')

    $tcp = @($rows | Where-Object { $_.Protocol -eq 'TCP' })
    $udp = @($rows | Where-Object { $_.Protocol -eq 'UDP' })
    $lst = @($tcp | Where-Object { $_.State -eq 'LISTENING' })

    $counts.Value.Tcp = $tcp.Count
    $counts.Value.Udp = $udp.Count
    $counts.Value.Listeners = $lst.Count

    return $true
  } catch {
    $note.Value = "netstat fallback failed: " + $_.Exception.Message
    return $false
  }
}

function Collect-Network {
  param([string]$outDir)

  $res = New-ResultObject 'Network'
  try {
    Ensure-Dir $outDir

    $counts = [ref](@{ Tcp=0; Listeners=0; Udp=0 })
    $note = [ref]$null

    $okNet = Try-CollectNetworkNetCmdlets -outDir $outDir -counts $counts -note $note
    if (-not $okNet) {
      $okNet = Collect-NetworkNetstatFallback -outDir $outDir -counts $counts -note $note
    }

    $res.Counts = $counts.Value
    if ($note.Value) { Add-Note $res $note.Value }

    if (-not $okNet) {
      Add-Error $res "network: no usable collection method"
    }
  } catch {
    Add-Error $res ("network: " + $_.Exception.Message)
    $res.Counts = @{ Tcp=0; Listeners=0; Udp=0 }
  }

  return $res
}

function Convert-TaskActionsToText {
  param([object[]]$Actions)

  if ($null -eq $Actions -or $Actions.Count -eq 0) { return '' }

  $parts = New-Object System.Collections.Generic.List[string]

  foreach ($a in $Actions) {
    try {
      $pnames = @($a.PSObject.Properties.Name)

      if ($pnames -contains 'Execute') {
        $exe = [string]$a.Execute
        $arg = $null
        if ($pnames -contains 'Arguments') { $arg = [string]$a.Arguments }

        if ($exe -and $arg)      { [void]$parts.Add(($exe + ' ' + $arg)) }
        elseif ($exe)            { [void]$parts.Add($exe) }
        else                     { [void]$parts.Add('[ExecAction]') }
        continue
      }

      if ($pnames -contains 'ClassId') {
        [void]$parts.Add(('[ComHandlerAction] ClassId=' + [string]$a.ClassId))
        continue
      }

      [void]$parts.Add(('[Action] ' + $a.GetType().FullName))
    } catch {
      [void]$parts.Add('[Action] <unreadable>')
    }
  }

  return ($parts -join ' | ')
}

function Export-SuspiciousTaskXml {
  param(
    [string]$outDir,
    [array]$taskRows,
    [int]$MaxXml
  )

  Ensure-Dir $outDir
  $exported = 0

  foreach ($t in ($taskRows | Where-Object { $_.Suspicious -eq $true })) {
    if ($exported -ge $MaxXml) { break }
    try {
      $safe = (($t.TaskPath + $t.TaskName) -replace '[\\/:*?"<>|]','_')
      $xmlPath = Join-Path $outDir ($safe + '.xml')
      Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath | Out-File -FilePath $xmlPath -Encoding UTF8
      $exported++
    } catch { }
  }

  return $exported
}

function Collect-Tasks {
  param([string]$outDir,$cat)

  $res = New-ResultObject 'Tasks'
  $rx=@(); try { $rx=@($cat.Tasks.SuspiciousRegex) } catch { }
  $exportXml = Safe-ToBool $cat.Tasks.ExportXmlForSuspicious $true
  $maxXml    = Safe-ToInt  $cat.Tasks.MaxXml 50

  try {
    Ensure-Dir $outDir

    $tasks = Get-ScheduledTask
    $flat = foreach ($t in $tasks) {
      $actions=@(); try { $actions=@($t.Actions) } catch { }
      $actionText = Convert-TaskActionsToText -Actions $actions

      $isSusp=$false
      foreach ($r in $rx) { if ($actionText -match $r) { $isSusp=$true; break } }

      $state=$null
      try { $state = (Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue).State } catch { }

      [pscustomobject]@{
        TaskName   = $t.TaskName
        TaskPath   = $t.TaskPath
        State      = $state
        Author     = $t.Principal.UserId
        Actions    = $actionText
        Suspicious = $isSusp
      }
    }

    $flat | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'tasks.csv')
    $res.Counts.Total = @($flat).Count
    $res.Counts.Suspicious = @($flat | Where-Object { $_.Suspicious }).Count

    if ($exportXml -and ($res.Counts.Suspicious -gt 0)) {
      $xmlDir = Join-Path $outDir 'xml'
      $exported = Export-SuspiciousTaskXml -outDir $xmlDir -taskRows $flat -MaxXml $maxXml
      $res.Counts.XmlExported = $exported
    } else {
      $res.Counts.XmlExported = 0
    }
  } catch {
    Add-Error $res ("tasks: " + $_.Exception.Message)
    $res.Counts.Total = 0
    $res.Counts.Suspicious = 0
    $res.Counts.XmlExported = 0
  }

  return $res
}

function Collect-WmiPersistence {
  param([string]$outDir)

  $res = New-ResultObject 'WMI'
  try {
    Ensure-Dir $outDir

    $filters  = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
    $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue

    $cmdConsumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    $asConsumers  = Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue
    $evConsumers  = Get-CimInstance -Namespace root\subscription -ClassName NTEventLogEventConsumer -ErrorAction SilentlyContinue
    $lfConsumers  = Get-CimInstance -Namespace root\subscription -ClassName LogFileEventConsumer -ErrorAction SilentlyContinue

    @($filters)      | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_eventfilters.csv')
    @($bindings)     | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_bindings.csv')
    @($cmdConsumers) | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_consumers_cmdline.csv')
    @($asConsumers)  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_consumers_activescript.csv')
    @($evConsumers)  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_consumers_eventlog.csv')
    @($lfConsumers)  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_consumers_logfile.csv')

    $res.Counts.Filters      = @($filters).Count
    $res.Counts.Bindings     = @($bindings).Count
    $res.Counts.Cmd          = @($cmdConsumers).Count
    $res.Counts.ActiveScript = @($asConsumers).Count
    $res.Counts.NTEventLog   = @($evConsumers).Count
    $res.Counts.LogFile      = @($lfConsumers).Count
  } catch {
    Add-Error $res ("wmi: " + $_.Exception.Message)
    $res.Counts = @{
      Filters=0; Bindings=0; Cmd=0; ActiveScript=0; NTEventLog=0; LogFile=0
    }
  }

  return $res
}

function Export-Autoruns {
  param([string]$outDir)

  $res = New-ResultObject 'Autoruns'
  try {
    Ensure-Dir $outDir

    $targets=@(
      'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
      'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
      'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
      'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    $rows = foreach ($k in $targets) {
      try {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        $p = Get-ItemProperty -Path $k -ErrorAction Stop
        foreach ($prop in $p.PSObject.Properties) {
          if ($prop.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
          [pscustomobject]@{ Key=$k; Name=$prop.Name; Value=[string]$prop.Value }
        }
      } catch {
        Add-Note $res ("autorun read failed: " + $k)
      }
    }

    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'autoruns_runkeys.csv')
    $res.Counts.Items = @($rows).Count
  } catch {
    Add-Error $res ("autoruns: " + $_.Exception.Message)
    $res.Counts.Items = 0
  }

  return $res
}

function Reset-Trigger {
  param($cat)
  try {
    $rk = [string]$cat.Trigger.Registry
    if ($rk -and (Test-Path -LiteralPath $rk)) {
      New-ItemProperty -Path $rk -Name 'Request' -PropertyType DWord -Value 0 -Force | Out-Null
    }
  } catch { }
}

function Print-ConsoleSummary {
  param(
    [hashtable]$Summary,
    [System.Collections.Generic.List[string]]$Errors,
    [bool]$Findings,
    [string]$CatalogLoadNote
  )

  Write-UiHeader -Title ("IR Grabber Summary (v{0})" -f $ScriptVersion) -Subtitle ("Host: {0} | Time: {1}" -f $Summary.Host,$Summary.Time)

  if ($CatalogLoadNote) {
    Write-UiStatus -Label 'Config' -State 'INFO' -Text $CatalogLoadNote
  }

  Write-UiKeyValue -Key 'WorkDir' -Value ([string]$Summary.Output.WorkDir)
  Write-UiKeyValue -Key 'Zip'     -Value ([string]$Summary.Output.Zip)

  Write-UiLine
  Write-Host "Counts:" -ForegroundColor Gray

  try { Write-Host ("  Processes : {0}" -f (Safe-ToInt $Summary.Counts.Processes 0)) -ForegroundColor White } catch { }

  try {
    $tcp = Safe-ToInt $Summary.Counts.Network.Tcp 0
    $lst = Safe-ToInt $Summary.Counts.Network.Listeners 0
    $udp = Safe-ToInt $Summary.Counts.Network.Udp 0
    Write-Host ("  Network   : TCP={0} Listeners={1} UDP={2}" -f $tcp,$lst,$udp) -ForegroundColor White
  } catch { }

  try {
    $tot = Safe-ToInt $Summary.Counts.Tasks.Total 0
    $sus = Safe-ToInt $Summary.Counts.Tasks.Suspicious 0
    $xml = Safe-ToInt $Summary.Counts.Tasks.XmlExported 0

    $c = 'White'
    if ($sus -gt 0) { $c = 'Yellow' }
    Write-Host ("  Tasks     : Total={0} Suspicious={1} XmlExported={2}" -f $tot,$sus,$xml) -ForegroundColor $c
  } catch { }

  try {
    $f = Safe-ToInt $Summary.Counts.WMI.Filters 0
    $b = Safe-ToInt $Summary.Counts.WMI.Bindings 0
    $c1 = Safe-ToInt $Summary.Counts.WMI.Cmd 0
    $a = Safe-ToInt $Summary.Counts.WMI.ActiveScript 0
    $e = Safe-ToInt $Summary.Counts.WMI.NTEventLog 0
    $l = Safe-ToInt $Summary.Counts.WMI.LogFile 0

    $wTotal = $f + $b + $c1 + $a + $e + $l
    $col = 'White'
    if ($wTotal -gt 0) { $col = 'Yellow' }

    Write-Host ("  WMI       : Filters={0} Bindings={1} Cmd={2} ActiveScript={3} NTEventLog={4} LogFile={5}" -f $f,$b,$c1,$a,$e,$l) -ForegroundColor $col
  } catch { }

  try { Write-Host ("  Autoruns  : Items={0}" -f (Safe-ToInt $Summary.Counts.Autoruns.Items 0)) -ForegroundColor White } catch { }

  try {
    if ($Summary.Counts.ContainsKey('Samples')) {
      $cop = Safe-ToInt $Summary.Counts.Samples.Copied 0
      $m1  = Safe-ToInt $Summary.Counts.Samples.MaxFileMB 0
      $m2  = Safe-ToInt $Summary.Counts.Samples.MaxTotalMB 0

      $col = 'White'
      if ($cop -gt 0) { $col = 'Yellow' }

      Write-Host ("  Samples   : Copied={0} (MaxFileMB={1}, MaxTotalMB={2})" -f $cop,$m1,$m2) -ForegroundColor $col
    }
  } catch { }

  Write-UiLine

  if ($Errors -and $Errors.Count -gt 0) {
    Write-UiStatus -Label 'Errors' -State 'WARN' -Text ("{0} error(s) occurred" -f $Errors.Count)
    foreach ($e in @($Errors)) { Write-Host ("  - {0}" -f $e) -ForegroundColor Yellow }
  } else {
    Write-UiStatus -Label 'Errors' -State 'OK' -Text "None"
  }

  if ($Findings) {
    Write-UiStatus -Label 'Findings' -State 'WARN' -Text "YES (review outputs)"
  } else {
    Write-UiStatus -Label 'Findings' -State 'OK' -Text "NO"
  }

  Write-UiLine
}

# -------------------------
# MAIN
# -------------------------
Ensure-EventSource

$errors   = New-Object System.Collections.Generic.List[string]
$findings = $false
$ok       = $true
$summary  = $null
$catalogNote = $null

try {
  Write-Information ("IR Grabber starting (v{0})" -f $ScriptVersion)

  $catRef = [ref]$null
  $cat = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath -CatalogLoadNote ([ref]$catalogNote)
  if (-not $cat) { $cat = New-BaseClone $DefaultCatalog }

  $tr = Read-Trigger -cat $cat -Force:$Force -CollectSamples:$CollectSamples
  if (-not $tr.Want) {
    $msg = "IR Grabber: no trigger set (registry/fileflag), aborted. Hint: run with -Force."
    Write-HealthEvent 10021 $msg 'Warning'

    $summary = [ordered]@{
      Host    = $env:COMPUTERNAME
      Time    = (Get-Date).ToString('s')
      Reason  = $tr.Reason
      Trigger = @{
        Registry = [string]$cat.Trigger.Registry
        FileFlag = [string]$cat.Trigger.FileFlag
        Force    = [bool]$Force
      }
      Output  = @{ WorkDir = $null; Zip = $null }
      Counts  = @{}
      Errors  = @()
      Notes   = @()
      Samples = @()
    }

    return
  }

  $ts = New-RunId

  $base = $null
  try { $base = [string]$cat.OutputBase } catch { $base = $null }
  if (-not $base) { $base = [string]$DefaultCatalog.OutputBase }

  $work = Join-Path $base $ts
  $zip  = Join-Path $base ("Grabber-{0}-{1}.zip" -f $env:COMPUTERNAME,$ts)

  Ensure-Dir $work

  $summary = [ordered]@{
    Host    = $env:COMPUTERNAME
    Time    = (Get-Date).ToString('s')
    Reason  = $tr.Reason
    Trigger = @{
      Registry = [string]$cat.Trigger.Registry
      FileFlag = [string]$cat.Trigger.FileFlag
      Force    = [bool]$Force
    }
    Output  = @{ WorkDir = $work; Zip = $zip }
    Counts  = @{}
    Errors  = @()
    Notes   = @()
    Samples = @()
  }

  # Processes
  $pDir = Join-Path $work 'process'
  $pRes = Collect-Processes -outDir $pDir -cat $cat -hashAll:$HashAllProcesses
  $summary.Counts.Processes = Safe-ToInt $pRes.Counts.Count 0
  if ($pRes.Errors.Count -gt 0) { $pRes.Errors | ForEach-Object { [void]$errors.Add($_) } }

  # Network
  $nDir = Join-Path $work 'network'
  $nRes = Collect-Network -outDir $nDir
  $summary.Counts.Network = $nRes.Counts
  if ($nRes.Errors.Count -gt 0) { $nRes.Errors | ForEach-Object { [void]$errors.Add($_) } }
  if ($nRes.Notes.Count -gt 0) { $summary.Notes += @($nRes.Notes) }

  # Tasks
  $tDir = Join-Path $work 'tasks'
  $tRes = Collect-Tasks -outDir $tDir -cat $cat
  $summary.Counts.Tasks = $tRes.Counts
  if ($tRes.Errors.Count -gt 0) { $tRes.Errors | ForEach-Object { [void]$errors.Add($_) } }
  if (Safe-ToInt $tRes.Counts.Suspicious 0 -gt 0) { $findings = $true }

  # WMI persistence
  $wDir = Join-Path $work 'wmi'
  $wRes = Collect-WmiPersistence -outDir $wDir
  $summary.Counts.WMI = $wRes.Counts
  if ($wRes.Errors.Count -gt 0) { $wRes.Errors | ForEach-Object { [void]$errors.Add($_) } }

  $wmiTotal = (Safe-ToInt $wRes.Counts.Filters 0) + (Safe-ToInt $wRes.Counts.Bindings 0) + (Safe-ToInt $wRes.Counts.Cmd 0) + (Safe-ToInt $wRes.Counts.ActiveScript 0) + (Safe-ToInt $wRes.Counts.NTEventLog 0) + (Safe-ToInt $wRes.Counts.LogFile 0)
  if ($wmiTotal -gt 0) { $findings = $true }

  # Autoruns
  $aDir = Join-Path $work 'autoruns'
  $aRes = Export-Autoruns -outDir $aDir
  $summary.Counts.Autoruns = $aRes.Counts
  if ($aRes.Errors.Count -gt 0) { $aRes.Errors | ForEach-Object { [void]$errors.Add($_) } }

  # Samples (optional)
  if ($tr.Samples -or (Safe-ToBool $cat.Samples.Enable $false)) {
    $sDir = Join-Path $work 'samples'
    Ensure-Dir $sDir

    $maxFileMB  = Safe-ToInt $tr.MaxFileMB (Safe-ToInt $cat.Samples.MaxFileSizeMB 20)
    $maxTotalMB = Safe-ToInt $tr.MaxTotalMB (Safe-ToInt $cat.Samples.MaxTotalMB 100)
    $totalBytes = [ref]([int64]0)

    $procCsv = Join-Path $pDir 'processes.csv'
    if (Test-Path -LiteralPath $procCsv) {
      $procList = Import-Csv -Path $procCsv
      foreach ($row in $procList) {
        $path = [string]$row.Path
        if (-not $path) { continue }
        if (-not (Test-Path -LiteralPath $path)) { continue }

        $pick = $false
        foreach ($rx in @($cat.Samples.PathIncludeRegex)) { if ($path -match $rx) { $pick = $true; break } }
        if (-not $pick) { continue }

        if (Safe-ToBool $cat.Samples.OnlyUnsignedOrUnknown $true) {
          if ($row.Signed -eq 'True') { continue }
        }

        $okc, $dstOrWhy = Copy-ToEvidence -Src $path -BaseDir $sDir -MaxFileSizeMB $maxFileMB -MaxTotalMB $maxTotalMB -runningTotalBytes $totalBytes
        $sha = $null
        if ($okc) { $sha = Get-FileSha256 $dstOrWhy }

        $summary.Samples += [pscustomobject]@{
          Source = $path
          Copied = [bool]$okc
          Info   = $dstOrWhy
          Sha256 = $sha
        }
      }
    } else {
      [void]$errors.Add("samples: processes.csv missing")
    }

    $copiedCount = @($summary.Samples | Where-Object { $_.Copied }).Count
    $summary.Counts.Samples = @{
      Copied     = $copiedCount
      MaxFileMB  = $maxFileMB
      MaxTotalMB = $maxTotalMB
    }
    if ($copiedCount -gt 0) { $findings = $true }
  }

  if ($errors.Count -gt 0) { $summary.Errors = @($errors) }
  Save-Json -Obj $summary -Path (Join-Path $work 'Summary.json')

  try {
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
    Compress-Archive -Path (Join-Path $work '*') -DestinationPath $zip -Force
  } catch {
    [void]$errors.Add("zip: " + $_.Exception.Message)
    $ok = $false
  }

  $msg = "IR Grabber: bundle created -> " + $zip
  if ($errors.Count -gt 0) { $msg = $msg + " | Errors: " + (@($errors) -join " | ") }

  $warn = ($errors.Count -gt 0) -or [bool]$Strict -or $findings -or (-not $ok)
  $eventId = 10020
  $level = 'Information'
  if ($warn) { $eventId = 10021; $level = 'Warning' }

  Write-HealthEvent $eventId $msg $level
  Reset-Trigger -cat $cat

} catch {
  $errMsg = "IR Grabber fatal: " + $_.Exception.Message
  [void]$errors.Add($errMsg)
  Write-HealthEvent 10021 $errMsg 'Error'
} finally {
  if ($null -ne $summary) {
    if ($errors.Count -gt 0) { $summary.Errors = @($errors) }
    try { Print-ConsoleSummary -Summary $summary -Errors $errors -Findings $findings -CatalogLoadNote $catalogNote } catch { }
  } else {
    Write-UiStatus -Label 'IR Grabber' -State 'FAIL' -Text "No summary object created."
  }
}
