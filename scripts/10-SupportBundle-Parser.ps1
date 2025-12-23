<#
.SYNOPSIS
Parses the newest SupportBundle ZIP in a folder, extracts key metadata, and returns a single structured result object for automation.

.DESCRIPTION
This script is designed for two audiences at the same time:
- Automation: It emits exactly one structured PowerShell object to the pipeline, so it can be filtered and exported cleanly (e.g. ConvertTo-Json, Export-Csv, Where-Object).
- Humans: It prints a readable console summary (with optional colors) without polluting the pipeline.

High-level workflow:
1) Locate the newest ZIP named 'SupportBundle-*.zip' under -SupportDir (by LastWriteTime).
2) Ensure a WorkDir exists by extracting the ZIP to -ExtractRoot\<ZipBaseName> (unless already extracted or -ForceExtract is used).
3) Load summary data:
   - First preference: adjacent '<ZipFullPath>.summary.json'
   - Fallback: 'Summary.json' inside the extracted WorkDir
4) Load an optional config JSON from -ConfigPath to determine which proof files are expected.
   If the config is missing or invalid, built-in defaults are used.
5) Determine proof presence for each expected proof file name:
   - Match by text markers found in Summary.Outputs (if present)
   - Match by file existence (directly in SearchDir and recursively below it)
6) Collect event log files (*.evtx) from 'WorkDir\eventlogs' (if that folder exists).
7) Load 'KBStatus.json' from WorkDir (root or recursively) and expose installed/missing KB lists if present.
8) Generate Findings based on missing markers/proofs and missing KBs (when available).
9) Print a console summary (optional colors), then return the result object to the pipeline.

.PARAMETER SupportDir
Folder that contains SupportBundle ZIP files.
The script searches this directory for 'SupportBundle-*.zip' and selects the newest file by LastWriteTime.

Default: PATH/TO/SUPPORT

.PARAMETER ConfigPath
Path to an optional configuration JSON that can define expected proof outputs.
If the file cannot be loaded or is invalid JSON, the script falls back to built-in defaults.

Default: PATH/TO/JSON/config.json

Expected config shape (optional):
- ProofOutFiles.SupportBundle
- ProofOutFiles.SysmonState
- ProofOutFiles.SysmonDriftState
- ProofOutFiles.SoftwareInventory
- ProofOutFiles.FirewallAudit
- ProofOutFiles.HardwareAudit

Only the leaf file names are used (Split-Path -Leaf).

.PARAMETER ExtractRoot
Root folder where ZIP files are extracted.
The WorkDir is created as: <ExtractRoot>\<ZipBaseName>

Default: PATH/TO/SUPPORT/_extracted

.PARAMETER ForceExtract
Forces re-extraction of the ZIP into the WorkDir even if files already exist there.
Use this if the extracted directory is incomplete or stale.

.PARAMETER ConsoleMode
Controls how the human-readable summary is printed:
- Host: Uses Write-Host (supports colors when -NoColor is not set).
- Information: Uses Write-Information only (no colors, easier to redirect/collect).

Default: Host

.PARAMETER NoColor
Disables colored output in Host mode.
Has no effect when -ConsoleMode Information is used.

.INPUTS
None. You cannot pipe objects into this script.

.OUTPUTS
System.Management.Automation.PSCustomObject

The script returns exactly one object with these top-level properties:

- Hostname (String)
  Hostname reported by the summary (if present).

- Time (String)
  Timestamp from the summary (if present).

- Reason (String)
  Reason field from the summary (if present).

- User (String)
  User field from the summary (if present).

- Admin (Boolean)
  Indicates whether the bundle was collected with administrative privileges (best-effort, defaults to $false).

- Errors (String[])
  Error messages reported by the summary (may be empty).

- Notes (String[])
  Combined notes from the summary plus script/runtime notes (e.g., config fallback notices).

- Outputs (String[])
  Raw output lines from the summary (may be empty).

- BundleZipName (String)
  File name of the selected ZIP.

- BundleZipPath (String)
  Full path to the selected ZIP.

- SummaryPath (String)
  Full path to the summary JSON that was successfully loaded.

- WorkDir (String)
  Extraction directory for the ZIP (may be $null if extraction failed).

- Proofs (PSCustomObject[])
  One element per expected proof file name:
  - FileName (String)
  - Present (Boolean)
  - PresentByOutput (Boolean)
  - PresentByFile (Boolean)
  - PresentByDirect (Boolean)
  - PresentByRecurse (Boolean)
  - FoundPath (String)

- EventLogDirExists (Boolean)
  True if 'WorkDir\eventlogs' exists.

- EventLogs (String[])
  Full paths of discovered *.evtx files (may be empty).

- KbStatus (PSCustomObject)
  - KbStatusPath (String)  Path that was searched/used
  - Present (Boolean)      True if KBStatus.json was found and parsed
  - Installed (Object[])   Raw array from KBStatus.json (if present)
  - MissingZeroDay (Object[])
  - MissingCritical (Object[])
  - Summary (Object)

- ZipMarkerPresent (Boolean)
  True if Summary.Outputs contains at least one entry matching 'ZIP:*'.

- Findings (String[])
  Human-readable findings derived from proof presence, ZIP marker presence, WorkDir availability, and KBStatus.

.EXAMPLE
PS> .\10-SupportBundle-Parser.ps1

Runs with defaults, prints a console summary, and returns the result object.

.EXAMPLE
PS> $r = .\10-SupportBundle-Parser.ps1 -SupportDir 'C:\PATH\TO\SUPPORT' -ExtractRoot 'C:\PATH\TO\SUPPORT\_extracted'
PS> $r.Proofs | Where-Object { -not $_.Present } | Select-Object FileName,FoundPath

Parses the newest bundle and lists missing proofs in a structured way.

.EXAMPLE
PS> .\10-SupportBundle-Parser.ps1 -ConsoleMode Information | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 '.\bundle-result.json'

Sends the object to the pipeline for JSON export while keeping console output on the Information stream.

.EXAMPLE
PS> .\10-SupportBundle-Parser.ps1 -ForceExtract -NoColor

Forces re-extraction and prints a plain (non-colored) console summary.

.NOTES
- The script is strict-mode friendly and treats summary/config fields as optional; missing properties are handled with defaults.
- Console output is intentionally separated from pipeline output to keep automation reliable.
- Extraction overwrites files when re-extracting; use a dedicated ExtractRoot to avoid collisions.
#>


[CmdletBinding()]
param(
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$SupportDir = "PATH/TO/SUPPORT",

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$ConfigPath = "PATH/TO/JSON/config.json",

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$ExtractRoot = "PATH/TO/SUPPORT/_extracted",

  [Parameter()]
  [switch]$ForceExtract,

  [Parameter()]
  [ValidateSet('Host','Information')]
  [string]$ConsoleMode = 'Host',

  [Parameter()]
  [switch]$NoColor
)

Set-StrictMode -Version Latest

# -------------------- Console helpers (no pipeline output) --------------------

function Get-ConsoleColor {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateSet('Header','Key','Value','Ok','Warn','Error','Muted')]
    [string]$Role
  )

  if ($script:NoColor) { return $null }

  switch ($Role) {
    'Header' { 'Cyan' }
    'Key'    { 'Gray' }
    'Value'  { 'White' }
    'Ok'     { 'Green' }
    'Warn'   { 'Yellow' }
    'Error'  { 'Red' }
    'Muted'  { 'DarkGray' }
  }
}

function Write-ConsoleLine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Text,

    [Parameter()]
    [ValidateSet('Header','Key','Value','Ok','Warn','Error','Muted')]
    [string]$Role = 'Value'
  )

  if ($null -eq $Text) { $Text = '' }

  if ($script:ConsoleMode -eq 'Information') {
    Write-Information -MessageData $Text -InformationAction Continue
    return
  }

  $c = Get-ConsoleColor -Role $Role
  if ($c) { Write-Host $Text -ForegroundColor $c } else { Write-Host $Text }  # Display-only output.
}

function Write-ConsoleHeader {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Title
  )

  Write-ConsoleLine -Text "============================================================" -Role Header
  Write-ConsoleLine -Text $Title -Role Header
  Write-ConsoleLine -Text "------------------------------------------------------------" -Role Header
}

function Write-ConsoleKV {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Key,

    [Parameter()]
    [AllowNull()]
    [object]$Value,

    [Parameter()]
    [ValidateSet('Value','Ok','Warn','Error','Muted')]
    [string]$ValueRole = 'Value'
  )

  $k = ('{0,-12}: ' -f $Key)

  $v = $Value
  if ($null -eq $v) { $v = '' }
  $v = "$v"

  if ($script:ConsoleMode -eq 'Information') {
    Write-Information -MessageData ($k + $v) -InformationAction Continue
    return
  }

  $keyColor = Get-ConsoleColor -Role Key
  if ($keyColor) { Write-Host $k -ForegroundColor $keyColor -NoNewline } else { Write-Host $k -NoNewline }

  $valueColor = if ($script:NoColor) { $null } else { Get-ConsoleColor -Role $ValueRole }
  if ($valueColor) { Write-Host $v -ForegroundColor $valueColor } else { Write-Host $v }
}

function ConvertTo-SafeDisplayPath {
  [CmdletBinding()]
  param(
    [Parameter()]
    [AllowNull()]
    [string]$Path
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

  $p = $Path
  $p = $p -replace '(?i)^[A-Z]:\\ProgramData\\[^\\]+\\', 'PATH\TO\APP\'
  $p = $p -replace '(?i)^[A-Z]:\\Users\\[^\\]+\\', 'PATH\TO\USER\'
  $p = $p -replace '(?i)^[A-Z]:\\', 'PATH\TO\DRIVE\'
  return $p
}

# -------------------- StrictMode-safe property access --------------------

function Get-PropValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [AllowNull()]
    [object]$Object,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Name,

    [Parameter()]
    [AllowNull()]
    $Default = $null
  )

  if ($null -eq $Object) { return $Default }

  $prop = $Object.PSObject.Properties.Item($Name)
  if ($null -eq $prop) { return $Default }

  return $prop.Value
}

function Get-PropArrayStrings {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [AllowNull()]
    [object]$Object,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Name
  )

  $v = Get-PropValue -Object $Object -Name $Name -Default $null
  if ($null -eq $v) { return @() }

  return @($v | ForEach-Object { "$_" })
}

function Coalesce-Bool {
  [CmdletBinding()]
  param(
    [Parameter()]
    $Value,

    [Parameter()]
    [bool]$Default = $false
  )

  if ($null -eq $Value) { return $Default }
  try { return [bool]$Value } catch { return $Default }
}

# -------------------- File/JSON helpers --------------------

function Ensure-Folder {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Path
  )

  if (Test-Path -LiteralPath $Path -PathType Container) { return $true }

  try {
    New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
    return $true
  }
  catch {
    Write-Warning ("Cannot create folder: {0} ({1})" -f (ConvertTo-SafeDisplayPath $Path), $_.Exception.Message)
    return $false
  }
}

function Load-JsonFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Path
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }

  try {
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
  }
  catch {
    Write-Warning ("Failed to parse JSON: {0} ({1})" -f (ConvertTo-SafeDisplayPath $Path), $_.Exception.Message)
    return $null
  }
}

function Get-LatestSupportBundleZip {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SupportDir
  )

  if (-not (Test-Path -LiteralPath $SupportDir -PathType Container)) { return $null }

  Get-ChildItem -LiteralPath $SupportDir -Filter 'SupportBundle-*.zip' -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
}

function Resolve-SummaryFromZip {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [System.IO.FileInfo]$Zip
  )

  $adjacentSummaryPath = "$($Zip.FullName).summary.json"
  if (Test-Path -LiteralPath $adjacentSummaryPath -PathType Leaf) {
    $summary = Load-JsonFile -Path $adjacentSummaryPath
    if ($summary) {
      return [pscustomobject]@{
        SummaryPath = $adjacentSummaryPath
        Summary     = $summary
      }
    }
  }

  return $null
}

function Ensure-ExtractedWorkDir {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ZipPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ExtractRoot,

    [Parameter()]
    [switch]$Force
  )

  if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) { return $null }
  [void](Ensure-Folder -Path $ExtractRoot)

  $zipItem = Get-Item -LiteralPath $ZipPath -ErrorAction Stop
  $dest = Join-Path -Path $ExtractRoot -ChildPath $zipItem.BaseName
  [void](Ensure-Folder -Path $dest)

  $needsExtract = $Force.IsPresent
  if (-not $needsExtract) {
    $anyFile = Get-ChildItem -LiteralPath $dest -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $anyFile) { $needsExtract = $true }
  }

  if ($needsExtract) {
    try {
      Expand-Archive -LiteralPath $zipItem.FullName -DestinationPath $dest -Force -ErrorAction Stop  # PS5.1.
    }
    catch {
      Write-Warning ("Failed to extract ZIP: {0} -> {1} ({2})" -f (ConvertTo-SafeDisplayPath $zipItem.FullName), (ConvertTo-SafeDisplayPath $dest), $_.Exception.Message)
      return $null
    }
  }

  return $dest
}

function Resolve-WorkDirAndSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [System.IO.FileInfo]$Zip,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ExtractRoot,

    [Parameter()]
    [switch]$ForceExtract
  )

  $notes = New-Object System.Collections.Generic.List[string]

  $workDir = Ensure-ExtractedWorkDir -ZipPath $Zip.FullName -ExtractRoot $ExtractRoot -Force:$ForceExtract
  if (-not $workDir) {
    $notes.Add("ZIP could not be extracted; only adjacent summary may be used (if present).")
  }

  $sum = Resolve-SummaryFromZip -Zip $Zip
  if ($sum) {
    return [pscustomobject]@{
      ZipPath     = $Zip.FullName
      ZipName     = $Zip.Name
      SummaryPath = $sum.SummaryPath
      WorkDir     = $workDir
      Summary     = $sum.Summary
      Notes       = @($notes)
    }
  }

  if ($workDir -and (Test-Path -LiteralPath $workDir -PathType Container)) {
    $workSummaryPath = Join-Path -Path $workDir -ChildPath 'Summary.json'
    if (Test-Path -LiteralPath $workSummaryPath -PathType Leaf) {
      $summary = Load-JsonFile -Path $workSummaryPath
      if ($summary) {
        return [pscustomobject]@{
          ZipPath     = $Zip.FullName
          ZipName     = $Zip.Name
          SummaryPath = $workSummaryPath
          WorkDir     = $workDir
          Summary     = $summary
          Notes       = @($notes)
        }
      }
    }
  }

  return $null
}

function Find-FileUnderDir {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Dir,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$FileName
  )

  if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { return $null }

  $hit = Get-ChildItem -LiteralPath $Dir -Recurse -File -Filter $FileName -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($hit) { return $hit.FullName }
  return $null
}

# -------------------- Domain logic --------------------

function Get-DefaultExpectedProofFiles {
  [CmdletBinding()]
  param()

  @(
    'SupportBundle.zip'
    'SysmonState.json'
    'SysmonDriftState.json'
    'SoftwareInventory.json'
    'FirewallAudit.json'
    'HardwareAudit.json'
  )
}

function Get-ExpectedProofFiles {
  [CmdletBinding()]
  param(
    [Parameter()]
    $ConfigObject
  )

  if (-not $ConfigObject) { return (Get-DefaultExpectedProofFiles) }
  if (-not ($ConfigObject.PSObject.Properties.Item('ProofOutFiles'))) { return (Get-DefaultExpectedProofFiles) }

  $p = $ConfigObject.ProofOutFiles
  if (-not $p) { return (Get-DefaultExpectedProofFiles) }

  $paths = @(
    (Get-PropValue -Object $p -Name 'SupportBundle' -Default $null)
    (Get-PropValue -Object $p -Name 'SysmonState' -Default $null)
    (Get-PropValue -Object $p -Name 'SysmonDriftState' -Default $null)
    (Get-PropValue -Object $p -Name 'SoftwareInventory' -Default $null)
    (Get-PropValue -Object $p -Name 'FirewallAudit' -Default $null)
    (Get-PropValue -Object $p -Name 'HardwareAudit' -Default $null)
  ) | Where-Object { $_ }

  if (-not $paths -or $paths.Count -eq 0) { return (Get-DefaultExpectedProofFiles) }

  $leaf = @()
  foreach ($x in $paths) {
    try { $leaf += (Split-Path -Path $x -Leaf) } catch { $leaf += "$x" }
  }
  return $leaf
}

function Get-ProofPresence {
  [CmdletBinding()]
  param(
    [Parameter()]
    [AllowNull()]
    [AllowEmptyCollection()]
    [string[]]$Outputs = @(),

    [Parameter()]
    [AllowNull()]
    [AllowEmptyCollection()]
    [string[]]$ExpectedProofFileNames = @(),

    [Parameter()]
    [AllowNull()]
    [string]$SearchDir
  )

  $outputsLocal  = @($Outputs)
  $expectedLocal = @($ExpectedProofFileNames)

  foreach ($fileName in $expectedLocal) {
    $pattern = [regex]::Escape($fileName)

    $presentByOutput = $false
    if ($outputsLocal.Count -gt 0) {
      $presentByOutput = [bool]($outputsLocal | Where-Object { $_ -match $pattern } | Select-Object -First 1)
    }

    $presentByDirect = $false
    $presentByRecurse = $false
    $foundPath = $null

    if ($SearchDir -and (Test-Path -LiteralPath $SearchDir -PathType Container)) {
      $candidate = Join-Path -Path $SearchDir -ChildPath $fileName
      if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        $presentByDirect = $true
        $foundPath = $candidate
      }
      else {
        $foundPath = Find-FileUnderDir -Dir $SearchDir -FileName $fileName
        if ($foundPath) { $presentByRecurse = $true }
      }
    }

    [pscustomobject]@{
      FileName          = $fileName
      Present           = ($presentByOutput -or $presentByDirect -or $presentByRecurse)
      PresentByOutput   = $presentByOutput
      PresentByFile     = ($presentByDirect -or $presentByRecurse)
      PresentByDirect   = $presentByDirect
      PresentByRecurse  = $presentByRecurse
      FoundPath         = $foundPath
    }
  }
}

function Get-EventLogFiles {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$WorkDir
  )

  $evDir = Join-Path -Path $WorkDir -ChildPath 'eventlogs'
  if (-not (Test-Path -LiteralPath $evDir -PathType Container)) {
    return [pscustomobject]@{ EventLogDirExists = $false; EventLogs = @() }
  }

  $evtx = Get-ChildItem -LiteralPath $evDir -Filter '*.evtx' -File -ErrorAction SilentlyContinue
  return [pscustomobject]@{ EventLogDirExists = $true; EventLogs = @($evtx.FullName) }
}

function Get-KBStatusSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$WorkDir
  )

  $kbStatusPath = Join-Path -Path $WorkDir -ChildPath 'KBStatus.json'
  if (-not (Test-Path -LiteralPath $kbStatusPath -PathType Leaf)) {
    $kbStatusPath = Find-FileUnderDir -Dir $WorkDir -FileName 'KBStatus.json'
  }

  if (-not $kbStatusPath) {
    return [pscustomobject]@{
      KbStatusPath    = (Join-Path -Path $WorkDir -ChildPath 'KBStatus.json')
      Present         = $false
      Installed       = @()
      MissingZeroDay  = @()
      MissingCritical = @()
      Summary         = $null
    }
  }

  $kb = Load-JsonFile -Path $kbStatusPath
  if (-not $kb) {
    return [pscustomobject]@{
      KbStatusPath    = $kbStatusPath
      Present         = $false
      Installed       = @()
      MissingZeroDay  = @()
      MissingCritical = @()
      Summary         = $null
    }
  }

  return [pscustomobject]@{
    KbStatusPath    = $kbStatusPath
    Present         = $true
    Installed       = @((Get-PropValue -Object $kb -Name 'Installed' -Default @()))
    MissingZeroDay  = @((Get-PropValue -Object $kb -Name 'MissingZeroDay' -Default @()))
    MissingCritical = @((Get-PropValue -Object $kb -Name 'MissingCritical' -Default @()))
    Summary         = (Get-PropValue -Object $kb -Name 'Summary' -Default $null)
  }
}

function New-Findings {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [bool]$ZipMarkerPresent,

    [Parameter()]
    [AllowNull()]
    [AllowEmptyCollection()]
    [pscustomobject[]]$Proofs = @(),

    [Parameter(Mandatory)]
    [bool]$WorkDirExists,

    [Parameter(Mandatory)]
    $KbStatus
  )

  $findings = @()

  if (-not $ZipMarkerPresent) {
    $findings += "ZIP marker (ZIP:*) not found in Outputs; bundle may be incomplete or formatted differently."
  }

  if ($Proofs -and (@($Proofs | Where-Object { -not $_.Present }).Count -gt 0)) {
    $findings += "At least one expected proof file is missing."
  }

  if (-not $WorkDirExists) {
    $findings += "WorkDir not found; event logs and KB status may be incomplete."
  }

  if ($KbStatus -and $KbStatus.Present) {
    if (@($KbStatus.MissingZeroDay).Count -gt 0) { $findings += "Missing zero-day KBs reported by KBStatus.json." }
    if (@($KbStatus.MissingCritical).Count -gt 0) { $findings += "Missing critical KBs reported by KBStatus.json." }
  }

  return $findings
}

# -------------------- Main --------------------

$script:ConsoleMode = $ConsoleMode
$script:NoColor     = [bool]$NoColor

[void](Ensure-Folder -Path $SupportDir)
[void](Ensure-Folder -Path $ExtractRoot)

$runNotes = New-Object System.Collections.Generic.List[string]

$zip = Get-LatestSupportBundleZip -SupportDir $SupportDir
if (-not $zip) {
  Write-Warning ("No SupportBundle-*.zip found in: {0}" -f (ConvertTo-SafeDisplayPath $SupportDir))
  return
}

$bundle = Resolve-WorkDirAndSummary -Zip $zip -ExtractRoot $ExtractRoot -ForceExtract:$ForceExtract
if (-not $bundle -or -not $bundle.Summary) {
  Write-Warning ("No Summary.json found for ZIP: {0}" -f $zip.Name)
  return
}

foreach ($n in @($bundle.Notes)) { if ($n) { $runNotes.Add($n) } }

$summary = $bundle.Summary

$summaryHostname = Get-PropValue -Object $summary -Name 'Hostname' -Default $null
$summaryTime     = Get-PropValue -Object $summary -Name 'Time'     -Default $null
$summaryReason   = Get-PropValue -Object $summary -Name 'Reason'   -Default $null
$summaryUser     = Get-PropValue -Object $summary -Name 'User'     -Default $null
$summaryAdmin    = Coalesce-Bool (Get-PropValue -Object $summary -Name 'Admin' -Default $null) $false

$summaryErrors   = Get-PropArrayStrings -Object $summary -Name 'Errors'
$summaryNotes    = Get-PropArrayStrings -Object $summary -Name 'Notes'
$outputs         = @((Get-PropArrayStrings -Object $summary -Name 'Outputs'))

$conf = Load-JsonFile -Path $ConfigPath
if (-not $conf) {
  $runNotes.Add(("Config not loaded; using defaults (ConfigPath={0})." -f (ConvertTo-SafeDisplayPath $ConfigPath)))
}

$expectedProofNames = @((Get-ExpectedProofFiles -ConfigObject $conf))

$workDir = $bundle.WorkDir
$workDirExists = $false
if ($workDir -and (Test-Path -LiteralPath $workDir -PathType Container)) { $workDirExists = $true }

$proofSearchDir = $null
if ($workDirExists) { $proofSearchDir = $workDir }
elseif ($bundle.SummaryPath) { $proofSearchDir = Split-Path -Path $bundle.SummaryPath -Parent }

$proofStatus = @(Get-ProofPresence -Outputs $outputs -ExpectedProofFileNames $expectedProofNames -SearchDir $proofSearchDir)

$eventInfo = [pscustomobject]@{ EventLogDirExists = $false; EventLogs = @() }
$kbInfo    = [pscustomobject]@{ KbStatusPath = $null; Present = $false; Installed = @(); MissingZeroDay = @(); MissingCritical = @(); Summary = $null }

if ($workDirExists) {
  $eventInfo = Get-EventLogFiles -WorkDir $workDir
  $kbInfo    = Get-KBStatusSummary -WorkDir $workDir
}
else {
  $runNotes.Add("WorkDir is not available; event logs and KB status may be missing.")
}

$zipMarkerPresent = $false
if ($outputs.Count -gt 0) {
  $zipMarkerPresent = [bool]($outputs | Where-Object { $_ -like 'ZIP:*' } | Select-Object -First 1)
}

$findings = New-Findings -ZipMarkerPresent $zipMarkerPresent -Proofs $proofStatus -WorkDirExists $workDirExists -KbStatus $kbInfo

$result = [pscustomobject]@{
  Hostname          = $summaryHostname
  Time              = $summaryTime
  Reason            = $summaryReason
  User              = $summaryUser
  Admin             = $summaryAdmin

  Errors            = @($summaryErrors)
  Notes             = @($summaryNotes + @($runNotes.ToArray()))
  Outputs           = @($outputs)

  BundleZipName     = $bundle.ZipName
  BundleZipPath     = $bundle.ZipPath
  SummaryPath       = $bundle.SummaryPath
  WorkDir           = $workDir

  Proofs            = @($proofStatus)

  EventLogDirExists = $eventInfo.EventLogDirExists
  EventLogs         = @($eventInfo.EventLogs)

  KbStatus          = $kbInfo

  ZipMarkerPresent  = $zipMarkerPresent
  Findings          = @($findings)
}

# Pipeline output: only the structured object.
#$result

# -------------------- Pretty console summary --------------------

$missingProofs      = @($result.Proofs | Where-Object { -not $_.Present })
$presentProofsCount = @($result.Proofs).Count - $missingProofs.Count

$errorsCount    = @($result.Errors).Count
$notesCount     = @($result.Notes).Count
$outputsCount   = @($result.Outputs).Count
$eventLogsCount = @($result.EventLogs).Count
$findingsCount  = @($result.Findings).Count

$adminRole = 'Muted'
if ($result.Admin) { $adminRole = 'Ok' }

$proofRole = 'Ok'
if ($missingProofs.Count -gt 0) { $proofRole = 'Warn' }

$errorsRole = 'Ok'
if ($errorsCount -gt 0) { $errorsRole = 'Error' }

$notesRole = 'Muted'
if ($notesCount -gt 0) { $notesRole = 'Warn' }

$outputsRole = 'Muted'
if ($outputsCount -gt 0) { $outputsRole = 'Ok' }

$eventRole = 'Muted'
if ($eventLogsCount -gt 0) { $eventRole = 'Ok' }

$kbRole = 'Muted'
$kbText = 'not present'
if ($result.KbStatus -and $result.KbStatus.Present) {
  $zd = @($result.KbStatus.MissingZeroDay).Count
  $cr = @($result.KbStatus.MissingCritical).Count
  $kbText = ("present (ZD missing: {0}, CR missing: {1})" -f $zd, $cr)
  $kbRole = 'Ok'
  if ($zd -gt 0 -or $cr -gt 0) { $kbRole = 'Warn' }
}

Write-ConsoleHeader -Title "SupportBundle summary"

Write-ConsoleKV -Key "Hostname" -Value $result.Hostname -ValueRole Value
Write-ConsoleKV -Key "Time"     -Value $result.Time     -ValueRole Value
if ($result.Reason) { Write-ConsoleKV -Key "Reason" -Value $result.Reason -ValueRole Value }
Write-ConsoleKV -Key "User"     -Value $result.User     -ValueRole Value
Write-ConsoleKV -Key "Admin"    -Value ($result.Admin.ToString()) -ValueRole $adminRole

Write-ConsoleLine -Text "" -Role Muted
Write-ConsoleKV -Key "ZIP"      -Value $result.BundleZipName -ValueRole Value
Write-ConsoleKV -Key "ZIPpath"  -Value (ConvertTo-SafeDisplayPath $result.BundleZipPath) -ValueRole Muted
Write-ConsoleKV -Key "WorkDir"  -Value (ConvertTo-SafeDisplayPath $result.WorkDir) -ValueRole Value
Write-ConsoleKV -Key "Summary"  -Value (ConvertTo-SafeDisplayPath $result.SummaryPath) -ValueRole Muted

Write-ConsoleLine -Text "" -Role Muted
Write-ConsoleKV -Key "Errors"    -Value $errorsCount  -ValueRole $errorsRole
Write-ConsoleKV -Key "Notes"     -Value $notesCount   -ValueRole $notesRole
Write-ConsoleKV -Key "Outputs"   -Value $outputsCount -ValueRole $outputsRole
Write-ConsoleKV -Key "Proofs"    -Value ("{0}/{1} present" -f $presentProofsCount, @($result.Proofs).Count) -ValueRole $proofRole
Write-ConsoleKV -Key "EventLogs" -Value ("{0} (dir: {1})" -f $eventLogsCount, $result.EventLogDirExists) -ValueRole $eventRole
Write-ConsoleKV -Key "KBStatus"  -Value $kbText -ValueRole $kbRole

Write-ConsoleLine -Text "" -Role Muted
if ($findingsCount -gt 0) {
  Write-ConsoleLine -Text "Findings:" -Role Warn
  foreach ($f in $result.Findings) { Write-ConsoleLine -Text ("- {0}" -f $f) -Role Warn }

  if ($missingProofs.Count -gt 0) {
    Write-ConsoleLine -Text "" -Role Muted
    Write-ConsoleLine -Text "Missing proofs:" -Role Warn
    foreach ($m in $missingProofs) {
      $fp = $m.FoundPath
      if ($fp) { $fp = ConvertTo-SafeDisplayPath $fp }
      if ([string]::IsNullOrWhiteSpace($fp)) { $fp = "<not found>" }
      Write-ConsoleLine -Text ("- {0} ({1})" -f $m.FileName, $fp) -Role Warn
    }
  }
}
else {
  Write-ConsoleLine -Text "Findings: none" -Role Ok
}

Write-ConsoleLine -Text "============================================================" -Role Header
