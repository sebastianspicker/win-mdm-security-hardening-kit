#requires -version 5.1
<#
.SYNOPSIS
Runs WinGet Configuration "validate", "test" and (optionally) "apply" with preflight checks, optional logging,
a console summary, and a reliable process exit code (PowerShell 5.1).

.DESCRIPTION
Best-practice output model:
- Pipeline output: structured objects only (safe for Export-Csv / ConvertTo-Json / Where-Object).
- Console output: separators and formatting use Write-UiLine / Write-Information only.

JSON sidecar (optional):
- If -SummaryJsonPath is not provided, the script tries:
  $PSScriptRoot\25-WinGet-Config-Baseline-Runner.json
- If JSON is missing or invalid, internal defaults are used.

.PARAMETER ConfigPath
Path to a WinGet configuration file (.yaml/.yml/.json).

.PARAMETER TestOnly
Run validate/test only; skip apply.

.PARAMETER AcceptAgreements
Auto-accept source/package agreements when running WinGet.

.PARAMETER LogPath
Optional log file path for command output.

.PARAMETER DisableInteractivity
Run WinGet in non-interactive mode.

.PARAMETER FailFast
Stop on first failing command.

.PARAMETER PassThru
Return structured objects to the pipeline.

.PARAMETER SummaryJsonPath
Optional JSON path for summary settings/overrides.

.PARAMETER QuietConsole
Suppress console summary output.

.PARAMETER ExtraArgs
Additional raw arguments passed to WinGet (alias: Args).


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

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
  .\25-WinGet-Config-Baseline-Runner.ps1

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $false)]
  [string]$ConfigPath,

  [switch]$TestOnly,

  [bool]$AcceptAgreements = $true,

  [string]$LogPath,

  [ValidateRange(1, 86400)]
  [int]$TimeoutSeconds = 300,

  [ValidateRange(1024, 10485760)]
  [int]$MaxOutputBytes = 1048576,

  [switch]$DisableInteractivity,

  [switch]$FailFast,

  # Best practice: default is NO pipeline output. Use -PassThru when you want objects.
  [switch]$PassThru,

  [string]$SummaryJsonPath,

  [switch]$QuietConsole,

  [Alias('Args')]
  [string[]]$ExtraArgs

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
. (Join-Path $PSScriptRoot 'internal/25-WinGet-Config-Baseline-Runner.helpers.ps1')


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '25-WinGet-Config-Baseline-Runner.ps1' -BoundParameters $PSBoundParameters `
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
  $result = Get-V2ResultObject -ScriptName '25-WinGet-Config-Baseline-Runner.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$script:Findings = Get-FindingsList

function Ensure-NotSystemContext {
  if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
      if ($identity.IsSystem) {
        throw "SYSTEM context detected: WinGet CLI is not supported; use Microsoft.WinGet.Client instead."
      }
    } finally {
      $identity.Dispose()
    }
  }
}

function Ensure-LogDirectory {
  param([Parameter(Mandatory = $true)][string]$FilePath)
  $dir = Split-Path -Path $FilePath -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
  }
}

function Add-BoundedUtf8Log {
  [OutputType([bool])]
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [AllowEmptyString()][string]$Text,
    [Parameter(Mandatory = $true)][int]$MaximumBytes
  )

  Ensure-LogDirectory -FilePath $Path
  $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
  try {
    $remaining = [math]::Max(0, $MaximumBytes - $stream.Length)
    if ($remaining -eq 0) { return (-not [string]::IsNullOrEmpty($Text)) }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $bytes = $encoding.GetBytes($Text)
    $truncated = ($bytes.Length -gt $remaining)
    if ($truncated) {
      $low = 0
      $high = $Text.Length
      while ($low -lt $high) {
        $mid = [int](($low + $high + 1) / 2)
        if ($encoding.GetByteCount($Text.Substring(0, $mid)) -le $remaining) { $low = $mid } else { $high = $mid - 1 }
      }
      $bytes = $encoding.GetBytes($Text.Substring(0, $low))
    }
    $stream.Position = $stream.Length
    if ($bytes.Length -gt 0) { $stream.Write($bytes, 0, $bytes.Length) }
    $stream.Flush($true)
    return $truncated
  } finally {
    $stream.Dispose()
  }
}

function Add-WinGetPhaseFindings {
  param([Parameter(Mandatory = $true)]$PhaseResult)

  if ($PhaseResult.TimedOut) {
    [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-Timeout' -Severity 'High' -Message ("WinGet phase '{0}' timed out." -f $PhaseResult.Phase) -Extra @{ Phase = $PhaseResult.Phase; DurationS = $PhaseResult.DurationS })
  }
  if ($PhaseResult.OutputTruncated -or $PhaseResult.StderrTruncated -or $PhaseResult.LogTruncated) {
    [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-OutputTruncated' -Severity 'Medium' -Message ("WinGet phase '{0}' output was truncated; evidence is partial." -f $PhaseResult.Phase) -Extra @{ Phase = $PhaseResult.Phase })
  }
  if (-not [string]::IsNullOrWhiteSpace([string]$PhaseResult.LogError)) {
    [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-LogFailed' -Severity 'Medium' `
        -Message ("WinGet phase '{0}' completed, but its requested log could not be written: {1}" -f $PhaseResult.Phase, $PhaseResult.LogError) `
        -Extra @{ Phase = $PhaseResult.Phase })
  }
  if ($PhaseResult.ExitCode -ne 0) {
    $severity = if ($PhaseResult.Phase -eq 'apply') { 'High' } else { 'Medium' }
    [void](Add-Finding -FindingList $script:Findings -Code ("WINGET-{0}Failed" -f $PhaseResult.Phase) -Severity $severity `
        -Message ("WinGet phase '{0}' failed with exit code {1}" -f $PhaseResult.Phase, $PhaseResult.ExitCode) `
        -Extra @{ Phase = $PhaseResult.Phase; ExitCode = $PhaseResult.ExitCode; DurationS = $PhaseResult.DurationS })
  }
}

function Complete-WinGetStagingCleanup {
  [CmdletBinding()]
  param([AllowNull()]$StagedConfiguration)

  if ($null -eq $StagedConfiguration) {
    return [pscustomobject]@{ Succeeded = $true; Error = $null }
  }
  try {
    Remove-WinGetStagedConfiguration -StagedConfiguration $StagedConfiguration
    return [pscustomobject]@{ Succeeded = $true; Error = $null }
  } catch {
    $message = $_.Exception.Message
    if ($message.Length -gt 1024) { $message = $message.Substring(0, 1024) + '...' }
    [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-StagingCleanupFailed' -Severity 'Medium' `
        -Message ("Protected WinGet staging cleanup failed: {0}" -f $message))
    return [pscustomobject]@{ Succeeded = $false; Error = $message }
  }
}

function To-BoolOrDefault {
  param($Value, [Parameter(Mandatory = $true)][bool]$Default)

  if ($null -eq $Value) { return $Default }
  if ($Value -is [bool]) { return [bool]$Value }

  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $Default }

  switch ($s.Trim().ToLowerInvariant()) {
    'true'  { return $true }
    'false' { return $false }
    '1'     { return $true }
    '0'     { return $false }
    default { return $Default }
  }
}

function To-StringOrNull {
  param($Value)
  if ($null -eq $Value) { return $null }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  return $s
}

function Get-EffectiveSetting {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][hashtable]$Json,
    [AllowNull()] $DefaultValue
  )

  if ($PSBoundParameters.ContainsKey($Name)) {
    return (Get-Variable -Name $Name -ValueOnly)
  }
  if ($Json -and $Json.ContainsKey($Name)) { return $Json[$Name] }
  return $DefaultValue
}




function Invoke-WinGet {
  param(
    [Parameter(Mandatory = $true)][string[]]$ArgsWinget,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Phase,
    [string]$LogPathEffective,
    [int]$TimeoutSecondsEffective,
    [int]$MaxOutputBytesEffective
  )

  $started = Get-Date

  if ([string]::IsNullOrWhiteSpace($script:WingetExecutablePath)) {
    throw 'Trusted WinGet executable path is unavailable.'
  }
  $native = Invoke-NativeCommand -Command $script:WingetExecutablePath -Arguments $ArgsWinget -CaptureOutput -Quiet `
    -TimeoutSeconds $TimeoutSecondsEffective -MaxOutputBytes $MaxOutputBytesEffective
  if ($null -eq $native) {
    $native = [pscustomobject]@{ ExitCode = -1; Output = ''; Stdout = ''; Stderr = ''; TimedOut = $false; OutputTruncated = $false; StderrTruncated = $false }
  }
  $logTruncated = $false
  $logError = $null
  if ($LogPathEffective -and $native) {
    $logText = ([string]$native.Stdout + [string]$native.Stderr)
    try {
      $logTruncated = Add-BoundedUtf8Log -Path $LogPathEffective -Text $logText -MaximumBytes $MaxOutputBytesEffective
    } catch {
      $logError = $_.Exception.Message
      if ($logError.Length -gt 1024) { $logError = $logError.Substring(0, 1024) + '...' }
    }
  }
  $ended = Get-Date

  [pscustomobject]@{
    Phase     = $Phase
    ExitCode  = [int]$native.ExitCode
    Started   = $started
    Ended     = $ended
    DurationS = [math]::Round((New-TimeSpan -Start $started -End $ended).TotalSeconds, 3)
    Args      = ($ArgsWinget -join ' ')
    TimedOut  = [bool]$native.TimedOut
    OutputTruncated = [bool]$native.OutputTruncated
    StderrTruncated = [bool]$native.StderrTruncated
    LogTruncated = [bool]$logTruncated
    LogError   = $logError
  }
}

function Get-SummaryObject {
  param(
    [string]$ConfigPathResolved,
    [System.Collections.Generic.List[object]]$Results,
    [int]$FinalExitCode,
    [bool]$TestOnlyEffective,
    [bool]$AcceptAgreementsEffective,
    [bool]$DisableInteractivityEffective,
    [bool]$FailFastEffective,
    [bool]$PassThruEffective,
    [bool]$QuietConsoleEffective,
    [string]$LogPathEffective,
    [string]$SummaryJsonPathEffective,
    [string[]]$ExtraArgsEffective,
    [string]$ErrorMessage
  )

  [pscustomobject]@{
    ComputerName         = $env:COMPUTERNAME
    ConfigPath           = $ConfigPathResolved
    TestOnly             = $TestOnlyEffective
    AcceptAgreements     = $AcceptAgreementsEffective
    DisableInteractivity = $DisableInteractivityEffective
    FailFast             = $FailFastEffective
    PassThru             = $PassThruEffective
    QuietConsole         = $QuietConsoleEffective
    SummaryJsonPath      = (To-StringOrNull $SummaryJsonPathEffective)
    LogPath              = $LogPathEffective
    ExtraArgs            = @($ExtraArgsEffective)
    Timestamp            = Get-Date
    Results              = @($Results.ToArray())
    FinalExitCode        = $FinalExitCode
    ErrorMessage         = (To-StringOrNull $ErrorMessage)
  }
}

function Invoke-WinGetConsoleSummary {
  param([Parameter(Mandatory = $true)][pscustomobject]$Summary)

  if ($Summary.QuietConsole) { return }

  $fields = [ordered]@{
    TestOnly             = [string]$Summary.TestOnly
    AcceptAgreements     = [string]$Summary.AcceptAgreements
    DisableInteractivity = [string]$Summary.DisableInteractivity
    FailFast             = [string]$Summary.FailFast
    FinalExitCode        = [string]$Summary.FinalExitCode
  }
  if ($Summary.ErrorMessage) { $fields['ErrorMessage'] = $Summary.ErrorMessage }

  $findingsAL = [System.Collections.ArrayList]::new()
  $findingsVar = Get-Variable -Name Findings -Scope Script -ErrorAction SilentlyContinue
  if ($findingsVar -and $findingsVar.Value) {
    foreach ($finding in @($findingsVar.Value.ToArray())) { [void]$findingsAL.Add($finding) }
  }
  Write-ConsoleSummary -Summary $Summary -Findings $findingsAL -CustomFields $fields

  # Phases list
  if ($Summary.Results -and $Summary.Results.Count -gt 0) {
    Write-UiLine ''
    Write-UiLine -Message 'Phases' -Style 'Header'
    foreach ($r in $Summary.Results) {
      $line = ("- {0,-8} ExitCode={1,-5} DurationS={2,-8}" -f $r.Phase, $r.ExitCode, $r.DurationS)
      if ($r.ExitCode -eq 0) {
        Write-UiLine -Message $line -Style 'Success'
      } else {
        Write-UiLine -Message $line -Style 'Error'
      }
    }
  } else {
    Write-UiLine ''
    Write-UiLine -Message 'Phases' -Style 'Header'
    Write-Warn "- (no phases executed)"
  }
}

function Write-UserFriendlyFailure {
  param(
    [Parameter(Mandatory = $true)][string]$Message,
    [Parameter(Mandatory = $true)][int]$ExitCode,
    [System.Collections.Generic.List[object]]$Results,
    [string]$ConfigPathResolved,
    [bool]$TestOnlyEffective,
    [bool]$AcceptAgreementsEffective,
    [bool]$DisableInteractivityEffective,
    [bool]$FailFastEffective,
    [bool]$PassThruEffective,
    [bool]$QuietConsoleEffective,
    [string]$LogPathEffective,
    [string]$SummaryJsonPathEffective,
    [string[]]$ExtraArgsEffective
  )

  if (-not $QuietConsoleEffective) {
    Write-UiLine -Message ("ERROR: {0}" -f $Message) -Style 'Error'
    Write-UiLine "Hint: Provide a configuration file with -ConfigPath, or set 'ConfigPath' in the summary JSON passed with -SummaryJsonPath." -Style 'Warning'
  }

  $safeResults = $Results
  if (-not $safeResults) { $safeResults = New-Object System.Collections.Generic.List[object] }

  $summary = Get-SummaryObject -ConfigPathResolved $ConfigPathResolved -Results $safeResults -FinalExitCode $ExitCode `
    -TestOnlyEffective $TestOnlyEffective -AcceptAgreementsEffective $AcceptAgreementsEffective -DisableInteractivityEffective $DisableInteractivityEffective `
    -FailFastEffective $FailFastEffective -PassThruEffective $PassThruEffective -QuietConsoleEffective $QuietConsoleEffective `
    -LogPathEffective $LogPathEffective -SummaryJsonPathEffective $SummaryJsonPathEffective -ExtraArgsEffective $ExtraArgsEffective -ErrorMessage $Message

  Invoke-WinGetConsoleSummary -Summary $summary

  $resultToken = if ($ExitCode -eq 2) { 'WARN' } else { 'FAIL' }
  if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
  Add-Finding -FindingList $script:Findings -Code 'WINGET-PreflightFailed' -Severity 'Medium' -Message $Message
  $v2Result = Get-V2ResultObject -ScriptName '25-WinGet-Config-Baseline-Runner.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings.ToArray()) -Summary $summary -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThruEffective) { $v2Result }
  exit (Get-V2ExitCode -Result $resultToken)
}

# Defaults
$defaultSettings = @{
  ConfigPath           = $null
  LogPath              = $null
  AcceptAgreements     = $true
  DisableInteractivity = $true
  FailFast             = $false

  # IMPORTANT: default is no pipeline output
  PassThru             = $false

  TestOnly             = $false
  QuietConsole         = $false
  Args                 = @()
}

# Default JSON sidecar path
if (-not $PSBoundParameters.ContainsKey('SummaryJsonPath')) {
  $SummaryJsonPath = Join-Path -Path $PSScriptRoot -ChildPath '25-WinGet-Config-Baseline-Runner.json'
}

$cfgResult = Read-ConfigWithDefaults -Path $SummaryJsonPath -Defaults @{} -AsHashtable -ReturnNullWhenMissing -ReturnNullOnError
$jsonSettings = $cfgResult.Config
if ($cfgResult.Meta.Error) {
  [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-ConfigLoadFailed' -Severity 'Medium' `
    -Message ("Summary JSON could not be loaded; using defaults. Error: {0}" -f $cfgResult.Meta.Error))
}
if (-not $jsonSettings) { $jsonSettings = @{} }

# Effective settings
$ConfigPathEffective = To-StringOrNull (Get-EffectiveSetting -Name 'ConfigPath' -Json $jsonSettings -DefaultValue $defaultSettings.ConfigPath)
if ($PSBoundParameters.ContainsKey('ConfigPath')) { $ConfigPathEffective = To-StringOrNull $ConfigPath }

$LogPathEffective = To-StringOrNull (Get-EffectiveSetting -Name 'LogPath' -Json $jsonSettings -DefaultValue $defaultSettings.LogPath)
if ($PSBoundParameters.ContainsKey('LogPath')) { $LogPathEffective = To-StringOrNull $LogPath }

$AcceptAgreementsEffective = To-BoolOrDefault (Get-EffectiveSetting -Name 'AcceptAgreements' -Json $jsonSettings -DefaultValue $defaultSettings.AcceptAgreements) -Default $defaultSettings.AcceptAgreements
if ($PSBoundParameters.ContainsKey('AcceptAgreements')) { $AcceptAgreementsEffective = [bool]$AcceptAgreements }

$DisableInteractivityEffective = To-BoolOrDefault (Get-EffectiveSetting -Name 'DisableInteractivity' -Json $jsonSettings -DefaultValue $defaultSettings.DisableInteractivity) -Default $defaultSettings.DisableInteractivity
if ($PSBoundParameters.ContainsKey('DisableInteractivity')) { $DisableInteractivityEffective = [bool]$DisableInteractivity }

$FailFastEffective = To-BoolOrDefault (Get-EffectiveSetting -Name 'FailFast' -Json $jsonSettings -DefaultValue $defaultSettings.FailFast) -Default $defaultSettings.FailFast
if ($PSBoundParameters.ContainsKey('FailFast')) { $FailFastEffective = [bool]$FailFast }

# PassThru can be enabled via JSON, but only if CLI didn't specify it.
$PassThruEffective = To-BoolOrDefault (Get-EffectiveSetting -Name 'PassThru' -Json $jsonSettings -DefaultValue $defaultSettings.PassThru) -Default $defaultSettings.PassThru
if ($PSBoundParameters.ContainsKey('PassThru')) { $PassThruEffective = [bool]$PassThru }

$TestOnlyEffective = To-BoolOrDefault (Get-EffectiveSetting -Name 'TestOnly' -Json $jsonSettings -DefaultValue $defaultSettings.TestOnly) -Default $defaultSettings.TestOnly
if ($PSBoundParameters.ContainsKey('TestOnly')) { $TestOnlyEffective = [bool]$TestOnly }
# Audit mode is intentionally validate/test only. Applying a WinGet
# configuration is a host mutation and must require explicit Remediate mode.
if ($Mode -eq 'Audit') { $TestOnlyEffective = $true }

$QuietConsoleEffective = To-BoolOrDefault (Get-EffectiveSetting -Name 'QuietConsole' -Json $jsonSettings -DefaultValue $defaultSettings.QuietConsole) -Default $defaultSettings.QuietConsole
if ($PSBoundParameters.ContainsKey('QuietConsole')) { $QuietConsoleEffective = [bool]$QuietConsole }

# Extra args
$ExtraArgsEffective = @()
if (($PSBoundParameters.ContainsKey('Args') -or $PSBoundParameters.ContainsKey('ExtraArgs')) -and $ExtraArgs) { $ExtraArgsEffective = @($ExtraArgs) }
elseif ($jsonSettings.ContainsKey('Args')) {
  $j = $jsonSettings['Args']
  if ($j -is [string]) { $ExtraArgsEffective = @($j) }
  elseif ($j -is [System.Collections.IEnumerable]) { $ExtraArgsEffective = @($j) }
}

# S12 fix: validate ExtraArgs against a blocklist of dangerous winget flags
if ($ExtraArgsEffective -and $ExtraArgsEffective.Count -gt 0) {
  $blockedFlags = @('--override', '--custom', '--ignore-security-hash', '--location',
                     '--log', '-o', '-h', '--header', '--authentication-account',
                     '--authentication-mode')
  foreach ($arg in $ExtraArgsEffective) {
    $argStr = [string]$arg
    # Block shell metacharacters
    if ($argStr -match '[;&|`$(){}<>]') {
      $message = "ExtraArgs contains shell metacharacters: '$argStr'. Aborting."
      [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-UnsafeExtraArgs' -Severity 'High' -Message $message)
      Write-UserFriendlyFailure -Message $message -ExitCode 1 -Results (New-Object System.Collections.Generic.List[object]) `
        -ConfigPathResolved $ConfigPathEffective -TestOnlyEffective $TestOnlyEffective -AcceptAgreementsEffective $AcceptAgreementsEffective `
        -DisableInteractivityEffective $DisableInteractivityEffective -FailFastEffective $FailFastEffective -PassThruEffective $PassThruEffective `
        -QuietConsoleEffective $QuietConsoleEffective -LogPathEffective $LogPathEffective -SummaryJsonPathEffective $SummaryJsonPath -ExtraArgsEffective $ExtraArgsEffective
    }
    # Block dangerous flags (case-insensitive, matching the flag portion before any '=' or space)
    $flagPart = ($argStr -split '[= ]', 2)[0]
    foreach ($blocked in $blockedFlags) {
      if ($flagPart -ieq $blocked) {
        $message = "ExtraArgs contains blocked flag '$argStr'. The flag '$blocked' is not allowed for safety reasons."
        [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-UnsafeExtraArgs' -Severity 'High' -Message $message)
        Write-UserFriendlyFailure -Message $message -ExitCode 1 -Results (New-Object System.Collections.Generic.List[object]) `
          -ConfigPathResolved $ConfigPathEffective -TestOnlyEffective $TestOnlyEffective -AcceptAgreementsEffective $AcceptAgreementsEffective `
          -DisableInteractivityEffective $DisableInteractivityEffective -FailFastEffective $FailFastEffective -PassThruEffective $PassThruEffective `
          -QuietConsoleEffective $QuietConsoleEffective -LogPathEffective $LogPathEffective -SummaryJsonPathEffective $SummaryJsonPath -ExtraArgsEffective $ExtraArgsEffective
      }
    }
  }
}

if ((-not $ExtraArgsEffective) -or ($ExtraArgsEffective.Count -eq 0)) {
  if (-not $QuietConsoleEffective) { Write-Info "Info: No extra -Args provided. Continuing without additional winget arguments." }
}

$results = New-Object System.Collections.Generic.List[object]
$script:WingetExecutablePath = $null

if ([string]::IsNullOrWhiteSpace($ConfigPathEffective)) {
  Write-UserFriendlyFailure -Message "ConfigPath is missing. Provide a configuration file with -ConfigPath, or set 'ConfigPath' in the summary JSON passed with -SummaryJsonPath." `
    -ExitCode 2 -Results $results -ConfigPathResolved $null -TestOnlyEffective $TestOnlyEffective -AcceptAgreementsEffective $AcceptAgreementsEffective `
    -DisableInteractivityEffective $DisableInteractivityEffective -FailFastEffective $FailFastEffective -PassThruEffective $PassThruEffective `
    -QuietConsoleEffective $QuietConsoleEffective -LogPathEffective $LogPathEffective -SummaryJsonPathEffective $SummaryJsonPath -ExtraArgsEffective $ExtraArgsEffective
}

$stagedConfiguration = $null
try {
  try {
    $script:WingetExecutablePath = Resolve-TrustedWingetPath
    if ([string]::IsNullOrWhiteSpace($script:WingetExecutablePath)) { throw 'Trusted WinGet executable not found.' }
    Ensure-NotSystemContext
    $stagedConfiguration = New-WinGetStagedConfiguration -SourcePath $ConfigPathEffective
    $resolvedConfigPath = $stagedConfiguration.SourcePath
    $executionConfigPath = $stagedConfiguration.Path
  } catch {
    $preflightMessage = $_.Exception.Message
    $cleanupOutcome = Complete-WinGetStagingCleanup -StagedConfiguration $stagedConfiguration
    if ($cleanupOutcome.Succeeded) { $stagedConfiguration = $null }
    Write-UserFriendlyFailure -Message $preflightMessage -ExitCode 1 -Results $results `
      -ConfigPathResolved $ConfigPathEffective -TestOnlyEffective $TestOnlyEffective -AcceptAgreementsEffective $AcceptAgreementsEffective `
      -DisableInteractivityEffective $DisableInteractivityEffective -FailFastEffective $FailFastEffective -PassThruEffective $PassThruEffective `
      -QuietConsoleEffective $QuietConsoleEffective -LogPathEffective $LogPathEffective -SummaryJsonPathEffective $SummaryJsonPath -ExtraArgsEffective $ExtraArgsEffective
  }

$argsCommon = @('configure')
if ($AcceptAgreementsEffective)     { $argsCommon += '--accept-configuration-agreements' }
if ($DisableInteractivityEffective) { $argsCommon += '--disable-interactivity' }
if ($ExtraArgsEffective -and $ExtraArgsEffective.Count -gt 0) { $argsCommon += $ExtraArgsEffective }

$argsValidate = @($argsCommon + @('validate', '-f', $executionConfigPath))
$argsTest     = @($argsCommon + @('test',     '-f', $executionConfigPath))
$argsApply    = @($argsCommon + @('-f', $executionConfigPath))

$rValidate = Invoke-WinGet -ArgsWinget $argsValidate -Phase 'validate' -LogPathEffective $LogPathEffective -TimeoutSecondsEffective $TimeoutSeconds -MaxOutputBytesEffective $MaxOutputBytes
$results.Add($rValidate) | Out-Null
Add-WinGetPhaseFindings -PhaseResult $rValidate
$validateSucceeded = Test-WinGetPhaseSuccess -PhaseResult $rValidate
$validateExitCode = Get-WinGetAggregateExitCode -PhaseResults @($rValidate)

if ($FailFastEffective -and -not $validateSucceeded) {
  $cleanupOutcome = Complete-WinGetStagingCleanup -StagedConfiguration $stagedConfiguration
  if ($cleanupOutcome.Succeeded) { $stagedConfiguration = $null }
  $summary = Get-SummaryObject -ConfigPathResolved $resolvedConfigPath -Results $results -FinalExitCode $validateExitCode `
    -TestOnlyEffective $TestOnlyEffective -AcceptAgreementsEffective $AcceptAgreementsEffective -DisableInteractivityEffective $DisableInteractivityEffective `
    -FailFastEffective $FailFastEffective -PassThruEffective $PassThruEffective -QuietConsoleEffective $QuietConsoleEffective `
    -LogPathEffective $LogPathEffective -SummaryJsonPathEffective $SummaryJsonPath -ExtraArgsEffective $ExtraArgsEffective -ErrorMessage "Validate failed."
  $summary | Add-Member -NotePropertyName StagingCleanupSucceeded -NotePropertyValue $cleanupOutcome.Succeeded -Force
  $summary | Add-Member -NotePropertyName StagingCleanupError -NotePropertyValue $cleanupOutcome.Error -Force
  Invoke-WinGetConsoleSummary -Summary $summary
  $resultToken = 'FAIL'
  $v2Result = Get-V2ResultObject -ScriptName '25-WinGet-Config-Baseline-Runner.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings.ToArray()) -Summary $summary -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThruEffective) { $v2Result }
  exit (Get-V2ExitCode -Result $resultToken)
}

$rTest = Invoke-WinGet -ArgsWinget $argsTest -Phase 'test' -LogPathEffective $LogPathEffective -TimeoutSecondsEffective $TimeoutSeconds -MaxOutputBytesEffective $MaxOutputBytes
$results.Add($rTest) | Out-Null
Add-WinGetPhaseFindings -PhaseResult $rTest
$testSucceeded = Test-WinGetPhaseSuccess -PhaseResult $rTest
$testExitCode = Get-WinGetAggregateExitCode -PhaseResults @($rTest)

if ($FailFastEffective -and -not $testSucceeded) {
  $cleanupOutcome = Complete-WinGetStagingCleanup -StagedConfiguration $stagedConfiguration
  if ($cleanupOutcome.Succeeded) { $stagedConfiguration = $null }
  $summary = Get-SummaryObject -ConfigPathResolved $resolvedConfigPath -Results $results -FinalExitCode $testExitCode `
    -TestOnlyEffective $TestOnlyEffective -AcceptAgreementsEffective $AcceptAgreementsEffective -DisableInteractivityEffective $DisableInteractivityEffective `
    -FailFastEffective $FailFastEffective -PassThruEffective $PassThruEffective -QuietConsoleEffective $QuietConsoleEffective `
    -LogPathEffective $LogPathEffective -SummaryJsonPathEffective $SummaryJsonPath -ExtraArgsEffective $ExtraArgsEffective -ErrorMessage "Test failed."
  $summary | Add-Member -NotePropertyName StagingCleanupSucceeded -NotePropertyValue $cleanupOutcome.Succeeded -Force
  $summary | Add-Member -NotePropertyName StagingCleanupError -NotePropertyValue $cleanupOutcome.Error -Force
  Invoke-WinGetConsoleSummary -Summary $summary
  $resultToken = 'FAIL'
  $v2Result = Get-V2ResultObject -ScriptName '25-WinGet-Config-Baseline-Runner.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings.ToArray()) -Summary $summary -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThruEffective) { $v2Result }
  exit (Get-V2ExitCode -Result $resultToken)
}

$rApply = $null
$preflightSucceeded = ($validateSucceeded -and $testSucceeded)
if (($Mode -eq 'Remediate') -and (-not $TestOnlyEffective) -and $preflightSucceeded) {
  # The apply phase is the only mutating WinGet phase in this runner; validate
  # and test can run in audit workflows, but apply stays behind ShouldProcess.
  if ($PSCmdlet.ShouldProcess($resolvedConfigPath, 'Run winget configure apply')) {
    $rApply = Invoke-WinGet -ArgsWinget $argsApply -Phase 'apply' -LogPathEffective $LogPathEffective -TimeoutSecondsEffective $TimeoutSeconds -MaxOutputBytesEffective $MaxOutputBytes
    $results.Add($rApply) | Out-Null
    Add-WinGetPhaseFindings -PhaseResult $rApply
  }
} elseif (($Mode -eq 'Remediate') -and (-not $TestOnlyEffective)) {
  [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-ApplyBlocked' -Severity 'High' `
      -Message 'WinGet apply was blocked because validate or test did not complete successfully.')
}

$failedPhases = @($results.ToArray() | Where-Object { $_.TimedOut -or $_.ExitCode -ne 0 })
$finalExitCode = Get-WinGetAggregateExitCode -PhaseResults $results.ToArray()
$finalErrorMessage = if ($failedPhases.Count -gt 0) { 'One or more WinGet phases failed or timed out.' } else { $null }
$cleanupOutcome = Complete-WinGetStagingCleanup -StagedConfiguration $stagedConfiguration
if ($cleanupOutcome.Succeeded) { $stagedConfiguration = $null }

$summary = Get-SummaryObject -ConfigPathResolved $resolvedConfigPath -Results $results -FinalExitCode $finalExitCode `
  -TestOnlyEffective $TestOnlyEffective -AcceptAgreementsEffective $AcceptAgreementsEffective -DisableInteractivityEffective $DisableInteractivityEffective `
  -FailFastEffective $FailFastEffective -PassThruEffective $PassThruEffective -QuietConsoleEffective $QuietConsoleEffective `
  -LogPathEffective $LogPathEffective -SummaryJsonPathEffective $SummaryJsonPath -ExtraArgsEffective $ExtraArgsEffective `
  -ErrorMessage $finalErrorMessage
$summary | Add-Member -NotePropertyName StagingCleanupSucceeded -NotePropertyValue $cleanupOutcome.Succeeded -Force
$summary | Add-Member -NotePropertyName StagingCleanupError -NotePropertyValue $cleanupOutcome.Error -Force

Invoke-WinGetConsoleSummary -Summary $summary

# V2 output contract
$resultToken = Get-WinGetResultToken -FinalExitCode $finalExitCode -FindingsCount $script:Findings.Count -StrictMode ([bool]$Strict)
$v2Result = Get-V2ResultObject -ScriptName '25-WinGet-Config-Baseline-Runner.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings.ToArray()) -Summary $summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThruEffective) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
} finally {
  if ($null -ne $stagedConfiguration) {
    try { Remove-WinGetStagedConfiguration -StagedConfiguration $stagedConfiguration }
    catch { Write-Warning "Failed to remove protected WinGet staging directory: $($_.Exception.Message)" }
  }
}
