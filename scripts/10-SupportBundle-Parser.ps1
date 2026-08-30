#requires -version 5.1
<#
.SYNOPSIS
Parses the newest SupportBundle ZIP in a folder, extracts key metadata, and returns a single structured result object for automation.
.DESCRIPTION
This script is designed for two audiences at the same time:
- Automation: With -PassThru, it emits exactly one structured PowerShell object to the pipeline, so it can be filtered and exported cleanly (e.g. ConvertTo-Json, Export-Csv, Where-Object).
- Humans: It prints a readable console summary (with optional colors) without polluting the pipeline.
High-level workflow:
1) Locate the newest ZIP named 'SupportBundle-*.zip' under -SupportDir (by LastWriteTime).
2) Safely extract the ZIP to a fresh directory below -ExtractRoot.
3) Load 'Summary.json' only from that validated extraction.  Sidecar summaries
   are deliberately not trusted because they can outlive or differ from a ZIP.
4) Load an optional config JSON from -ConfigPath to determine which proof files are expected.
   If the config is missing or invalid, built-in defaults are used.
5) Determine proof presence for each expected proof file name:
   - Match by legacy text markers found in Summary.Outputs (if present)
   - Match by file existence (directly in SearchDir and recursively below it)
6) Collect event log files (*.evtx) from 'WorkDir\eventlogs' (if that folder exists).
7) Load 'KBStatus.json' from WorkDir (root or recursively) and expose installed/missing KB lists if present.
8) Generate Findings based on failed producer records, missing proofs, and missing KBs (when available).
9) Print a console summary (optional colors), then return the result object to the pipeline.
.PARAMETER SupportDir
Folder that contains SupportBundle ZIP files.
The script searches this directory for 'SupportBundle-*.zip' and selects the newest file by LastWriteTime.
Default: %ProgramData%\BaselineOpsForWindows\SupportBundles
.PARAMETER ConfigPath
Path to an optional configuration JSON that can define expected proof outputs.
If the file cannot be loaded or is invalid JSON, the script falls back to built-in defaults.
Default: <script directory>\support-bundle.json
Expected config shape (optional):
- ProofOutFiles.SysmonState
- ProofOutFiles.SysmonDriftState
- ProofOutFiles.SoftwareInventory
- ProofOutFiles.FirewallAudit
- ProofOutFiles.HardwareAudit
Only the leaf file names are used (Split-Path -Leaf).
.PARAMETER ExtractRoot
Protected root where ZIP files are extracted. For elevated parsing this path is
fixed to %ProgramData%\BaselineOpsForWindows\SupportBundles\_extracted;
an explicitly supplied value must resolve to that same path. Each run uses a
fresh, uniquely named WorkDir below the protected root.
.PARAMETER ForceExtract
Compatibility switch. Extraction already uses a fresh WorkDir on every run, so
stale files are never reused.
.PARAMETER ConsoleMode
Controls how the human-readable summary is printed:
- Host: Uses Write-UiLine (supports colors when -NoColor is not set).
- Information: Uses Write-Information only (no colors, easier to redirect/collect).
Default: Host
.PARAMETER NoColor
Disables colored output in Host mode.
Has no effect when -ConsoleMode Information is used.
.INPUTS
None. You cannot pipe objects into this script.
.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.
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
.OUTPUTS
System.Management.Automation.PSCustomObject
With -PassThru, the script returns exactly one V2 result object whose Summary
contains these parser properties:
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
  Error messages reported by legacy summaries plus failed Records entries (may be empty).
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
- BundleArchiveValidated (Boolean)
  True after the selected ZIP has been safely extracted with a valid Summary.json.
- ZipMarkerPresent (Boolean)
  Compatibility alias for BundleArchiveValidated. New producer summaries do not emit Outputs ZIP markers.
- Findings (String[])
  Human-readable findings derived from producer failures, proof presence, WorkDir availability, and KBStatus.
.EXAMPLE
PS> .\10-SupportBundle-Parser.ps1 -PassThru
Runs with defaults, prints a console summary, and returns the result object.
.EXAMPLE
PS> $r = .\10-SupportBundle-Parser.ps1 -SupportDir $SupportDir -PassThru
PS> $r.Proofs | Where-Object { -not $_.Present } | Select-Object FileName,FoundPath
Parses the newest bundle and lists missing proofs in a structured way.
.EXAMPLE
PS> .\10-SupportBundle-Parser.ps1 -ConsoleMode Information -PassThru | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 '.\bundle-result.json'
Sends the object to the pipeline for JSON export while keeping console output on the Information stream.
.EXAMPLE
PS> .\10-SupportBundle-Parser.ps1 -ForceExtract -NoColor
Forces re-extraction and prints a plain (non-colored) console summary.
.NOTES
- The script is strict-mode friendly and treats summary/config fields as optional; missing properties are handled with defaults.
- Console output is intentionally separated from pipeline output to keep automation reliable.
- Extraction uses a fresh protected directory for every run and never reuses stale contents.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$SupportDir,
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$ConfigPath,
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$ExtractRoot,
  [Parameter()]
  [switch]$ForceExtract,
  [Parameter()]
  [ValidateSet('Host','Information')]
  [string]$ConsoleMode = 'Host',
  [Parameter()]
  [switch]$NoColor
,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet
)
. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'JsonCatalog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '10-SupportBundle-Parser.ps1' -BoundParameters $PSBoundParameters `
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
  $result = Get-V2ResultObject -ScriptName '10-SupportBundle-Parser.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# Canonical findings are initialized before path-policy validation so every
# supported-host preflight failure still terminates through the V2 contract.
$script:Findings = Get-FindingsList

# Keep parser defaults aligned with the producer's fixed, administrator-owned
# ProgramData root.  These are resolved after the host check because the
# script intentionally has no non-Windows execution contract.
$commonApplicationData = if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
  # Pester exercises Windows behavior from a non-Windows host using a scoped
  # ProgramData value. Windows resolves CommonApplicationData.
  $env:ProgramData
} else {
  [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
}
if ([string]::IsNullOrWhiteSpace($commonApplicationData)) { throw 'CommonApplicationData could not be resolved.' }
$defaultSupportDir = Join-Path (Join-Path $commonApplicationData 'BaselineOpsForWindows') 'SupportBundles'
$trustedExtractRoot = Join-Path $defaultSupportDir '_extracted'
if ([string]::IsNullOrWhiteSpace($SupportDir)) { $SupportDir = $defaultSupportDir }
if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = Join-Path $PSScriptRoot 'support-bundle.json' }
if ([string]::IsNullOrWhiteSpace($ExtractRoot)) { $ExtractRoot = $trustedExtractRoot }

$extractRootAllowed = $false
try {
  $extractRootAllowed = [System.IO.Path]::GetFullPath($ExtractRoot).Equals(
    [System.IO.Path]::GetFullPath($trustedExtractRoot),
    [System.StringComparison]::OrdinalIgnoreCase)
} catch {
  $extractRootAllowed = $false
}
if (-not $extractRootAllowed) {
  $message = 'ExtractRoot must equal the fixed CommonApplicationData support-bundle extraction root.'
  Add-Finding -FindingList $script:Findings -Code 'SB-UntrustedExtractRoot' -Severity 'High' -Message $message
  $summary = [pscustomobject]@{ Error = $message; SupportDir = $SupportDir; ConfigPath = $ConfigPath; ExtractRoot = $ExtractRoot }
  $v2Result = Get-V2ResultObject -ScriptName '10-SupportBundle-Parser.ps1' -Mode $Mode -Result 'FAIL' -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $summary -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit (Get-V2ExitCode -Result 'FAIL')
}
$ExtractRoot = [System.IO.Path]::GetFullPath($trustedExtractRoot)
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
function ConvertTo-SafeDisplayPath {
  [CmdletBinding()]
  param(
    [Parameter()]
    [AllowNull()]
    [string]$Path
  )
  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  $p = $Path
  $p = $p -replace '(?i)^[A-Z]:\\ProgramData\\[^\\]+\\', '[application data]\'
  $p = $p -replace '(?i)^[A-Z]:\\Users\\[^\\]+\\', '[user profile]\'
  $p = $p -replace '(?i)^[A-Z]:\\', '[local drive]\'
  return $p
}
function ConvertTo-SafeFindingDetail {
  [CmdletBinding()]
  param(
    [Parameter()]
    [AllowNull()]
    [AllowEmptyString()]
    [string]$Value
  )
  if ([string]::IsNullOrWhiteSpace($Value)) { return '<no detail supplied>' }
  $detail = ($Value -replace '[\x00-\x1F\x7F]', ' ').Trim()
  if ([string]::IsNullOrWhiteSpace($detail)) { return '<no detail supplied>' }
  if ($detail.Length -gt 1024) { $detail = $detail.Substring(0, 1024) + '...' }
  return $detail
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
# Ensure-Directory imported from lib/Common.psm1
# Load-JsonFile replaced by Read-JsonFileSafe from lib/JsonCatalog.psm1
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
. (Join-Path $PSScriptRoot 'internal/10-SupportBundle-Parser.helpers.ps1')
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
    return $null
  }
  if ($workDir -and (Test-Path -LiteralPath $workDir -PathType Container)) {
    $workSummaryPath = Join-Path -Path $workDir -ChildPath 'Summary.json'
    if (Test-Path -LiteralPath $workSummaryPath -PathType Leaf) {
      $summary = Read-JsonFileSafe -Path $workSummaryPath
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
function Exit-ParserFailure {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Message)
  Add-Finding -FindingList $script:Findings -Code 'SB-ParserFailure' -Severity 'High' -Message $Message
  $summary = [pscustomobject]@{ Error = $Message; SupportDir = $SupportDir; ConfigPath = $ConfigPath; ExtractRoot = $ExtractRoot }
  $v2Result = Get-V2ResultObject -ScriptName '10-SupportBundle-Parser.ps1' -Mode $Mode -Result 'FAIL' -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $summary -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit 1
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
  $kb = Read-JsonFileSafe -Path $kbStatusPath
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
function Invoke-FindingsCheck {
  [CmdletBinding()]
  param(
    [Parameter()]
    [AllowNull()]
    [AllowEmptyCollection()]
    [pscustomobject[]]$Proofs = @(),
    [Parameter(Mandatory)]
    [bool]$WorkDirExists,
    [Parameter(Mandatory)]
    $KbStatus
  )
  # Preserve the compatibility summary while also producing shared findings.
  $legacyFindings = @()
  if ($Proofs -and (@($Proofs | Where-Object { -not $_.Present }).Count -gt 0)) {
    $msg = "At least one expected proof file is missing."
    Add-Finding -FindingList $script:Findings -Code 'SB-MissingProof' -Severity 'Medium' -Message $msg
    $legacyFindings += $msg
  }
  if (-not $WorkDirExists) {
    $msg = "WorkDir not found; event logs and KB status may be incomplete."
    Add-Finding -FindingList $script:Findings -Code 'SB-NoWorkDir' -Severity 'Low' -Message $msg
    $legacyFindings += $msg
  }
  if ($KbStatus -and $KbStatus.Present) {
    if (@($KbStatus.MissingZeroDay).Count -gt 0) {
      $msg = "Missing zero-day KBs reported by KBStatus.json."
      Add-Finding -FindingList $script:Findings -Code 'SB-MissingZeroDayKB' -Severity 'High' -Message $msg
      $legacyFindings += $msg
    }
    if (@($KbStatus.MissingCritical).Count -gt 0) {
      $msg = "Missing critical KBs reported by KBStatus.json."
      Add-Finding -FindingList $script:Findings -Code 'SB-MissingCriticalKB' -Severity 'Medium' -Message $msg
      $legacyFindings += $msg
    }
  }
  return $legacyFindings
}
# -------------------- Main --------------------
$script:ConsoleMode = $ConsoleMode
$script:NoColor     = [bool]$NoColor
$runNotes = New-Object System.Collections.Generic.List[string]
$zip = Get-LatestSupportBundleZip -SupportDir $SupportDir
if (-not $zip) {
  Exit-ParserFailure -Message ("No SupportBundle-*.zip found in: {0}" -f (ConvertTo-SafeDisplayPath $SupportDir))
}
$bundle = Resolve-WorkDirAndSummary -Zip $zip -ExtractRoot $ExtractRoot -ForceExtract:$ForceExtract
if (-not $bundle -or -not $bundle.Summary) {
  Exit-ParserFailure -Message ("ZIP could not be safely extracted with a valid Summary.json: {0}" -f $zip.Name)
}
foreach ($n in @($bundle.Notes)) { if ($n) { $runNotes.Add($n) } }
$summary = $bundle.Summary
$summaryHostname = Get-PropValue -Object $summary -Name 'Hostname' -Default $null
$summaryTime     = Get-PropValue -Object $summary -Name 'Time'     -Default $null
$summaryReason   = Get-PropValue -Object $summary -Name 'Reason'   -Default $null
$summaryUser     = Get-PropValue -Object $summary -Name 'User'     -Default $null
$summaryAdmin    = Coalesce-Bool (Get-PropValue -Object $summary -Name 'Admin' -Default $null) $false
$legacySummaryErrors = @(Get-PropArrayStrings -Object $summary -Name 'Errors')
$summaryNotes    = @(Get-PropArrayStrings -Object $summary -Name 'Notes')
$outputs         = @((Get-PropArrayStrings -Object $summary -Name 'Outputs'))
$producerRecordErrors = New-Object System.Collections.Generic.List[string]
$summaryRecords = @((Get-PropValue -Object $summary -Name 'Records' -Default @()))
foreach ($record in $summaryRecords) {
  if ($null -eq $record) { continue }
  $recordOk = Get-PropValue -Object $record -Name 'Ok' -Default $null
  if ($recordOk -isnot [bool] -or $recordOk) { continue }

  $recordName = ConvertTo-SafeFindingDetail -Value ([string](Get-PropValue -Object $record -Name 'Name' -Default '<unnamed>'))
  $recordError = [string](Get-PropValue -Object $record -Name 'Error' -Default $null)
  if ([string]::IsNullOrWhiteSpace($recordError)) {
    $recordError = [string](Get-PropValue -Object $record -Name 'Note' -Default $null)
  }
  $safeDetail = ConvertTo-SafeFindingDetail -Value $recordError
  $producerRecordErrors.Add(("{0}: {1}" -f $recordName, $safeDetail))
  Add-Finding -FindingList $script:Findings -Code 'SB-ProducerError' -Severity 'Medium' `
    -Message ("SupportBundle producer record '{0}' failed: {1}" -f $recordName, $safeDetail) `
    -Extra @{ RecordName = $recordName } | Out-Null
}
$summaryErrors = @(@($legacySummaryErrors) + @($producerRecordErrors.ToArray()))
foreach ($producerError in @($legacySummaryErrors)) {
  $safeDetail = ConvertTo-SafeFindingDetail -Value $producerError
  Add-Finding -FindingList $script:Findings -Code 'SB-ProducerError' -Severity 'Medium' -Message ("SupportBundle producer reported an error: {0}" -f $safeDetail) | Out-Null
}
$conf = Read-JsonFileSafe -Path $ConfigPath
if (-not $conf) { $runNotes.Add(("Config not loaded; using defaults (ConfigPath={0})." -f (ConvertTo-SafeDisplayPath $ConfigPath))) }
$expectedProofNames = @((Get-ExpectedProofFiles -ConfigObject $conf))
$workDir = $bundle.WorkDir
$workDirExists = $false
if ($workDir -and (Test-Path -LiteralPath $workDir -PathType Container)) { $workDirExists = $true }
$proofSearchDir = $null
if ($workDirExists) { $proofSearchDir = $workDir }
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
$bundleArchiveValidated = $true
$legacyFindings = Invoke-FindingsCheck -Proofs $proofStatus -WorkDirExists $workDirExists -KbStatus $kbInfo
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
  BundleArchiveValidated = $bundleArchiveValidated
  ZipMarkerPresent  = $bundleArchiveValidated
  Findings          = @($legacyFindings)
}
# The legacy parser payload remains available as the V2 Summary; do not emit it
# separately because -PassThru has an exactly-one-object contract.
# -------------------- Formatted console summary --------------------
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
Write-KeyValue -Key "Hostname" -Value $result.Hostname -ValueRole Value
Write-KeyValue -Key "Time"     -Value $result.Time     -ValueRole Value
if ($result.Reason) { Write-KeyValue -Key "Reason" -Value $result.Reason -ValueRole Value }
Write-KeyValue -Key "User"     -Value $result.User     -ValueRole Value
Write-KeyValue -Key "Admin"    -Value ($result.Admin.ToString()) -ValueRole $adminRole
Write-ConsoleLine -Text "" -Role Muted
Write-KeyValue -Key "ZIP"      -Value $result.BundleZipName -ValueRole Value
Write-KeyValue -Key "ZIPpath"  -Value (ConvertTo-SafeDisplayPath $result.BundleZipPath) -ValueRole Muted
Write-KeyValue -Key "WorkDir"  -Value (ConvertTo-SafeDisplayPath $result.WorkDir) -ValueRole Value
Write-KeyValue -Key "Summary"  -Value (ConvertTo-SafeDisplayPath $result.SummaryPath) -ValueRole Muted
Write-ConsoleLine -Text "" -Role Muted
Write-KeyValue -Key "Errors"    -Value $errorsCount  -ValueRole $errorsRole
Write-KeyValue -Key "Notes"     -Value $notesCount   -ValueRole $notesRole
Write-KeyValue -Key "Outputs"   -Value $outputsCount -ValueRole $outputsRole
Write-KeyValue -Key "Proofs"    -Value ("{0}/{1} present" -f $presentProofsCount, @($result.Proofs).Count) -ValueRole $proofRole
Write-KeyValue -Key "EventLogs" -Value ("{0} (dir: {1})" -f $eventLogsCount, $result.EventLogDirExists) -ValueRole $eventRole
Write-KeyValue -Key "KBStatus"  -Value $kbText -ValueRole $kbRole
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
# V2 output contract
$resultToken = if (@($script:Findings).Count -gt 0) { 'WARN' } else { 'OK' }
if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
$v2Result = Get-V2ResultObject -ScriptName '10-SupportBundle-Parser.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $result -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
