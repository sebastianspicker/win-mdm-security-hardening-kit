#requires -version 5.1
<#
.SYNOPSIS
  Performs a health check and optional self-healing actions for WinGet on a Windows device.
.DESCRIPTION
  This script validates a working WinGet environment and produces both:
  - A colorized console summary.
  - A structured, automation-friendly result object for the pipeline.
  The script is designed for enterprise automation scenarios (scheduled tasks, MDM, build workers),
  but can also be run interactively by administrators.
  High-level workflow:
  1) Load optional JSON configuration (if available) and merge with parameter overrides.
  2) Detect WinGet and validate the installed WinGet version against the built-in minimum.
  3) Check Microsoft Visual C++ Redistributables:
     - x64 is required (missing => Error).
     - x86 is optional (missing => Warning).
     In Remediate mode, if installer paths are available, the script attempts installation.
  4) Validate presence of a private WinGet source when RequirePrivateSource is enabled.
     In Remediate mode, the script can add the missing source from a validated name, URL, and type.
  5) In Remediate mode, run "winget source update" to refresh sources.
     A failure is Warning by default, or Error when -FailOnSourceUpdateError is set.
  6) Write a short audit message to the Windows Application Event Log (best-effort).
  7) Print a final console summary and return structured results to the pipeline.
  Output conventions:
  - Pipeline output is always structured objects only (no formatted strings).
  - Console output uses Write-UiLine / Write-Information only and is suppressed with -NoConsole.
.PARAMETER RequirePrivateSource
  Controls whether a private WinGet source is required for an overall "OK" status.
  - $true  : Missing private source => overall NOT OK.
  - $false : Private source check is marked as Skipped and does not influence overall status.
.PARAMETER ConfigPath
  Path to an optional JSON configuration file.
  If the file does not exist or cannot be parsed, the script continues with defaults and parameter
  overrides and marks the Config check as Warning.
  The JSON (if present) can provide an audit-only private source name.
  Remediation authority for installers and source endpoints is accepted only
  from explicit operator parameters.
.PARAMETER PrivateSourceName
  Sets/overrides the private WinGet source name.
  Use this when no JSON is available or when you want to override the JSON value.
.PARAMETER PrivateSourceUrl
  Sets/overrides the private WinGet source URL.
  Required as an explicit operator parameter when remediation may add a source.
  It must be an HTTPS endpoint path without credentials, query, or fragment
  components. Configure source authentication out of band through the
  organization-managed WinGet or OS credential mechanism.
.PARAMETER InstallerX64Path
  Explicit operator-selected path to the Microsoft x64 VC++ Redistributable installer.
  Configuration files cannot grant installer execution authority.
.PARAMETER InstallerX86Path
  Explicit operator-selected path to the Microsoft x86 VC++ Redistributable installer.
  Configuration files cannot grant installer execution authority.
.PARAMETER FailOnSourceUpdateError
  Controls how "winget source update" failures affect the overall result.
  - Not set: source update failure is recorded as Warning.
  - Set:     source update failure is recorded as Error (overall NOT OK).
.PARAMETER DiagnoseWingetErrors
  Adds extended error details for failing WinGet calls by running:
  "winget error --input <ExitCode>".
  This helps translate WinGet HRESULT-style return codes into readable messages.
.PARAMETER NoConsole
  Suppresses all console output.
  Use this for silent automation runs where only pipeline output is desired.
.PARAMETER PassThruRecords
  Changes pipeline output mode:
  - Not set (default): outputs one result object containing a Records array.
  - Set:              outputs each record in the Records array as a separate pipeline object.
.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.
  In Remediate mode, the script may install missing VC++ Redistributables and add a missing private WinGet source when configured.
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
  Default output (single object):
    PSCustomObject with:
    - Time                 : Timestamp of the run.
    - OverallStatus        : 'OK' or 'NOT_OK'.
    - Remediate            : Boolean indicating whether remediation was enabled.
    - RequirePrivateSource : Boolean indicating whether private source was required.
    - ConfigPath           : The configured (anonymized) config path used by the run.
    - WingetVersion        : Raw WinGet version string (when available).
    - Records              : Array of check records.
  With -PassThruRecords:
    PSCustomObject (one per check) with:
    - Time, Name, Status, Message, Data
.NOTES
  Exit codes:
  - 0 = OK, 2 = WARN, 1 = FAIL.
  Event Log:
  The script attempts to write an audit entry to the Windows Application event log.
  This is best-effort and does not fail the run if event log write access is unavailable.
  Configuration precedence:
  Parameter values override JSON values, and JSON values override built-in defaults.
.EXAMPLE
  PS C:\> .\08-WinGet-SelfHeal.ps1
  Runs health checks only (no remediation) and prints a console summary.
  Returns a single structured result object to the pipeline.
.EXAMPLE
  PS C:\> .\08-WinGet-SelfHeal.ps1 -NoConsole | ConvertTo-Json -Depth 6
  Runs in "pipeline-only" mode and emits a JSON report suitable for logging.
.EXAMPLE
  PS C:\> .\08-WinGet-SelfHeal.ps1 -Mode Remediate -PrivateSourceName $PrivateSourceName -PrivateSourceUrl $PrivateSourceUrl -DiagnoseWingetErrors
  Runs checks and attempts remediation.
  The source name and URL variables must contain reviewed organization values.
  If the private source is missing, the script attempts to add it.
  Also includes additional WinGet error decoding on failures.
.EXAMPLE
  PS C:\> .\08-WinGet-SelfHeal.ps1 -PassThruRecords | Where-Object Status -ne 'OK'
  Emits each record as a pipeline object and filters for non-OK results.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [bool]$RequirePrivateSource = $true,
  [string]$ConfigPath,
  [string]$PrivateSourceName = $null,
  [string]$PrivateSourceUrl  = $null,
  [string]$InstallerX64Path,
  [string]$InstallerX86Path,
  [switch]$FailOnSourceUpdateError,
  [switch]$DiagnoseWingetErrors,
  [switch]$NoConsole,
  [switch]$PassThruRecords
,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)
. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
$script:NoConsole = [bool]$NoConsole
$script:PassThruRecords = [bool]$PassThruRecords
Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '08-WinGet-SelfHeal.ps1' -BoundParameters $PSBoundParameters `
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
  $resultToken = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '08-WinGet-SelfHeal.ps1' -Mode $Mode -Result $resultToken -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $resultToken)
}

# ---------------- Defaults ----------------
$MinWingetVersionMajor = 1
$MinWingetVersionMinor = 6
$MinWingetVersionPatch = 0
$DefaultVcArgs = "/install /quiet /norestart"
$DefaultPrivateSourceType = "Microsoft.Rest"
$EventSource  = "WinGet-SelfHeal"
$EventLogName = "Application"
# ---------------- Console Helpers ----------------
# Get-StatusColor imported from lib/Console.psm1
# ---------------- Event Log Helpers ----------------
# ---------------- Structured Output Helpers ----------------
function Get-TextOrEmpty {
  [CmdletBinding()]
  param([AllowNull()][AllowEmptyString()]$Value)
  if ($null -eq $Value) { return '' }
  return [string]$Value
}
function Get-CheckRecord {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [ValidateSet('OK','Warning','Error','Skipped')] [string]$Status,
    [string]$Message = $null,
    [hashtable]$Data = $null
  )
  [pscustomobject]@{
    Time    = (Get-Date).ToString('s')
    Name    = $Name
    Status  = $Status
    Message = $Message
    Data    = if ($Data) { [pscustomobject]$Data } else { $null }
  }
}
function Add-Record {
  [CmdletBinding()]
  param(
    # Collections must allow empty, otherwise PS rejects empty collections during binding.
    [ValidateNotNull()]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[object]]$List,
    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [object]$Record
  )
  [void]$List.Add($Record)
}
function Get-OverallOk {
  [CmdletBinding()]
  param([AllowNull()][object[]]$Records)
  if ($null -eq $Records -or $Records.Count -eq 0) { return $false }
  foreach ($r in $Records) {
    if ($null -ne $r -and $r.Status -eq 'Error') { return $false }
  }
  return $true
}
function Protect-WingetProcessMetadata {
  [CmdletBinding()]
  [OutputType([string])]
  param([AllowNull()][AllowEmptyString()]$Value)

  if ($null -eq $Value) { return '' }
  # Process output and arguments can echo a legacy or rejected source URL.
  # Do not let URL userinfo enter records, pipeline output, or event logging.
  return [regex]::Replace(
    [string]$Value,
    '(?i)https?://[^\s]*(?:@|\?|#)[^\s]*',
    '[credential-bearing URL redacted]'
  )
}
function Get-PrivateSourceResultMetadata {
  [CmdletBinding()]
  [OutputType([hashtable])]
  param(
    [AllowNull()][string]$Name,
    [AllowNull()][string]$Type
  )

  # Source endpoints are execution inputs, not result metadata. Authentication
  # must be provisioned separately and must never be carried in the URL.
  return @{ Name = $Name; Type = $Type; Endpoint = '[not recorded]' }
}
# ---------------- Config Helpers ----------------
function Get-Config {
  [CmdletBinding()]
  param([string]$Path)
  try {
    $sanitized = Sanitize-Path -Path $Path -MustExist
    if ($sanitized) {
      $configItem = Get-Item -LiteralPath $sanitized -Force -ErrorAction Stop
      if ($configItem.Length -gt 1MB) { throw 'Configuration file exceeds the 1 MiB size limit.' }
      return Get-BoundedUtf8FileContent -Path $sanitized -MaximumBytes 1048576 | ConvertFrom-Json
    }
  } catch {
    Write-Verbose ("WinGet config read failed: {0}" -f $_.Exception.Message)
  }
  return $null
}
function Get-NestedPropValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$Object,
    [Parameter(Mandatory)][string[]]$Path
  )
  $cur = $Object
  foreach ($name in $Path) {
    if ($null -eq $cur) { return $null }
    try {
      $prop = $cur.PSObject.Properties[$name]
      if ($null -eq $prop) { return $null }
      $cur = $prop.Value
    } catch { return $null }
  }
  return $cur
}
# ---------------- WinGet Helpers ----------------
function Resolve-WingetPath {
  [CmdletBinding()]
  param()
  return (Resolve-TrustedWingetPath)
}
function Invoke-Winget {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [Parameter(Mandatory)][string[]]$WingetArgs,
    [ValidateRange(1, 86400)][int]$TimeoutSec = 120
  )
  $native = Invoke-NativeCommand -Command $WingetPath -Arguments $WingetArgs -CaptureOutput -Quiet -TimeoutSeconds $TimeoutSec -MaxOutputBytes 1048576
  $metadataArgs = @($WingetArgs | ForEach-Object { Protect-WingetProcessMetadata -Value $_ })
  if ($null -eq $native) {
    return @{ ExitCode = 1; StdOut = ''; StdErr = 'winget process could not be started.'; Args = $metadataArgs; TimedOut = $false; OutputTruncated = $false; StderrTruncated = $false; Success = $false }
  }
  $timedOut = [bool]$native.TimedOut
  $truncated = [bool]$native.OutputTruncated -or [bool]$native.StderrTruncated
  $exitCode = if ($timedOut) { 408 } elseif ($truncated) { 413 } else { [int]$native.ExitCode }
  $stdout = Protect-WingetProcessMetadata -Value $native.Stdout
  $stderr = Protect-WingetProcessMetadata -Value $native.Stderr
  if ($timedOut) { $stderr = (($stderr, "Timeout after $TimeoutSec s" | Where-Object { $_ }) -join "`n") }
  if ($truncated) { $stderr = (($stderr, 'Output truncated at 1048576 bytes; result is unusable.' | Where-Object { $_ }) -join "`n") }
  return @{ ExitCode = $exitCode; StdOut = $stdout; StdErr = $stderr; Args = $metadataArgs; TimedOut = $timedOut; OutputTruncated = [bool]$native.OutputTruncated; StderrTruncated = [bool]$native.StderrTruncated; Success = ([bool]$native.Success -and -not $timedOut -and -not $truncated) }
}
function ConvertTo-ConservativeNativeArguments {
  [CmdletBinding()]
  param([AllowEmptyString()][string]$ArgumentString)
  if ([string]::IsNullOrWhiteSpace($ArgumentString)) { return @() }
  if ($ArgumentString -match '[\x00-\x1F\x7F]') { throw 'Installer arguments contain control characters.' }
  $arguments = New-Object System.Collections.Generic.List[string]
  $token = New-Object System.Text.StringBuilder
  $inQuotes = $false; $started = $false
  for ($index = 0; $index -lt $ArgumentString.Length; $index++) {
    $character = $ArgumentString[$index]
    if ($character -eq '"') {
      if ($index -gt 0 -and $ArgumentString[$index - 1] -eq '\') { throw 'Installer arguments must not use escaped quotes.' }
      $inQuotes = -not $inQuotes; $started = $true; continue
    }
    if ([char]::IsWhiteSpace($character) -and -not $inQuotes) {
      if ($started) { [void]$arguments.Add($token.ToString()); $token.Clear() | Out-Null; $started = $false }
      continue
    }
    [void]$token.Append($character); $started = $true
  }
  if ($inQuotes) { throw 'Installer arguments contain an unclosed quote.' }
  if ($started) { [void]$arguments.Add($token.ToString()) }
  return $arguments.ToArray()
}
function Convert-ExitCodeToHex32 {
  [CmdletBinding()]
  param([Parameter(Mandatory)][int]$ExitCode)
  $bytes = [System.BitConverter]::GetBytes([int]$ExitCode)
  $u = [System.BitConverter]::ToUInt32($bytes, 0)
  return ("0x{0:X8}" -f $u)
}
function Get-WingetErrorText {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [Parameter(Mandatory)][int]$ExitCode
  )
  try {
    $res = Invoke-Winget -WingetPath $WingetPath -WingetArgs @('error','--input',"$ExitCode") -TimeoutSec 30
    $t = ($res.StdOut + "`n" + $res.StdErr).Trim()
    if ($t) { return $t }
  } catch {
    Write-Verbose ("winget error diagnostic lookup failed: {0}" -f $_.Exception.Message)
  }
  return $null
}
function Parse-Version {
  [CmdletBinding()]
  param([string]$s)
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $m = [regex]::Match($s, 'v?(\d+)\.(\d+)\.(\d+)')
  if (-not $m.Success) { $m = [regex]::Match($s, 'v?(\d+)\.(\d+)') }
  if (-not $m.Success) { return $null }
  $maj = [int]$m.Groups[1].Value
  $min = [int]$m.Groups[2].Value
  $pat = 0
  if ($m.Groups.Count -ge 4 -and $m.Groups[3].Value) { $pat = [int]$m.Groups[3].Value }
  return [pscustomobject]@{ Major=$maj; Minor=$min; Patch=$pat; Raw=$s.Trim() }
}
function Is-Version-AtLeast {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$v,
    [Parameter(Mandatory)][int]$maj,
    [Parameter(Mandatory)][int]$min,
    [int]$pat = 0
  )
  if (-not $v) { return $false }
  if ($v.Major -gt $maj) { return $true }
  if ($v.Major -lt $maj) { return $false }
  if ($v.Minor -gt $min) { return $true }
  if ($v.Minor -lt $min) { return $false }
  return ($v.Patch -ge $pat)
}
function Test-WingetSupportsAcceptSourceAgreements {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$WingetPath)
  try {
    $h = Invoke-Winget -WingetPath $WingetPath -WingetArgs @('source','update','--help') -TimeoutSec 30
    $t = ($h.StdOut + "`n" + $h.StdErr)
    if ($t -match '--accept-source-agreements') { return $true }
  } catch {
    Write-Verbose ("winget source update help check failed: {0}" -f $_.Exception.Message)
  }
  return $false
}
function Invoke-WingetSourceUpdate {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [string]$SourceName,
    [bool]$SupportAcceptSourceAgreements
  )
  # Use "-n <name>" for compatibility with documented syntax.
  $wingetArgs = @('source','update')
  if ($SourceName) { $wingetArgs += @('-n', $SourceName) }
  if ($SupportAcceptSourceAgreements) { $wingetArgs += '--accept-source-agreements' }
  return Invoke-Winget -WingetPath $WingetPath -WingetArgs $wingetArgs
}
# ---------------- VC++ Helpers ----------------
function Test-VcRedistInstalled {
  [CmdletBinding()]
  param([ValidateSet('x64','x86')]$Arch='x64')
  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\$Arch",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\$Arch"
  )
  foreach ($key in $paths) {
    if (Test-Path $key) {
      try {
        $p = Get-ItemProperty -Path $key -ErrorAction Stop
        $installed = ($p.Installed -eq 1) -or ($p.PSObject.Properties['Version'] -and $p.Version)
        if ($installed) { return $true, ($p.Version) }
      } catch {
        Write-Verbose ("VC++ redistributable registry probe failed for '{0}': {1}" -f $key,$_.Exception.Message)
      }
    }
  }
  return $false, $null
}
function Install-VcRedist {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string]$InstallArgs = "/install /quiet /norestart",
    [ValidateSet('x64','x86')][string]$Architecture = 'x64'
  )
  $installerStream = $null
  try {
    $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (-not (Test-Path -LiteralPath $providerPath -PathType Leaf)) { return $false, "Installer not found: $Path" }
    $volumeRoot = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($providerPath))
    if (Test-PathContainsReparsePoint -Path $providerPath -Root $volumeRoot) {
      return $false, 'Installer path contains a reparse point.'
    }

    $resolvedPath = (Resolve-Path -LiteralPath $providerPath -ErrorAction Stop).ProviderPath
    $installerItem = Get-Item -LiteralPath $resolvedPath -Force -ErrorAction Stop
    if ($installerItem.Length -le 0 -or $installerItem.Length -gt 128MB) {
      return $false, 'Installer size is outside the accepted range.'
    }

    # FileShare.Read denies writes, replacement, and deletion while the trust
    # decision and process launch are in progress, closing the validation/use race.
    $installerStream = [System.IO.File]::Open(
      $resolvedPath,
      [System.IO.FileMode]::Open,
      [System.IO.FileAccess]::Read,
      [System.IO.FileShare]::Read
    )

    if ($env:OS -eq 'Windows_NT') {
      $signature = Get-AuthenticodeSignature -LiteralPath $resolvedPath -ErrorAction Stop
      $signerSubject = if ($null -ne $signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { '' }
      if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
          $signerSubject -notmatch '(?i)(^|,\s*)O=Microsoft Corporation(,|$)') {
        return $false, 'Installer must have a valid Microsoft Authenticode signature.'
      }

      $expectedOriginalName = "VC_redist.$Architecture.exe"
      $originalName = [string]$installerItem.VersionInfo.OriginalFilename
      if (-not $originalName.Equals($expectedOriginalName, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $false, "Installer identity does not match $expectedOriginalName."
      }
    }

    $arguments = ConvertTo-ConservativeNativeArguments -ArgumentString $InstallArgs
    if (-not $PSCmdlet.ShouldProcess($resolvedPath, "Install VC++ $Architecture redistributable")) {
      return $false, 'Skipped by ShouldProcess'
    }
    $native = Invoke-NativeCommand -Command $resolvedPath -Arguments $arguments -CaptureOutput -Quiet -TimeoutSeconds 600 -MaxOutputBytes 1048576
    if ($null -eq $native) { return $false, 'Installer process could not be started.' }
    if ($native.TimedOut) { return $false, 'Installer timed out after 600 s.' }
    if ($native.OutputTruncated -or $native.StderrTruncated) { return $false, 'Installer output was truncated; result is unusable.' }
    if ($native.Success) { return $true, 'OK' }
    return $false, "ExitCode=$($native.ExitCode)"
  } catch { return $false, $_.Exception.Message }
  finally {
    if ($null -ne $installerStream) { $installerStream.Dispose() }
  }
}
# ---------------- Source Helpers ----------------
function Test-WingetSourceOutputContainsName {
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [AllowNull()][AllowEmptyString()][string]$Text,
    [Parameter(Mandatory)][string]$Name
  )

  foreach ($line in @($Text -split '\r?\n')) {
    $propertyMatch = [regex]::Match($line, '^\s*Name\s*:\s*(?<Name>.+?)\s*$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($propertyMatch.Success -and $propertyMatch.Groups['Name'].Value.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
      return $true
    }

    $tableMatch = [regex]::Match($line, '^\s*(?<Name>\S+)\s+https://\S+', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($tableMatch.Success -and $tableMatch.Groups['Name'].Value.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
      return $true
    }
  }

  return $false
}

function Test-WingetSourcePresent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [Parameter(Mandatory)][string]$Name
  )
  $res = Invoke-Winget -WingetPath $WingetPath -WingetArgs @('source','list','-n',$Name)
  if ($res.ExitCode -eq 0) {
    if (Test-WingetSourceOutputContainsName -Text $res.StdOut -Name $Name) { return $true, "Found via 'source list -n'" }
  }
  $res2 = Invoke-Winget -WingetPath $WingetPath -WingetArgs @('source','list')
  if ($res2.ExitCode -eq 0 -and (Test-WingetSourceOutputContainsName -Text $res2.StdOut -Name $Name)) {
    return $true, "Found via 'source list'"
  }
  $err = (($res.StdErr + "`n" + $res.StdOut).Trim())
  if (-not $err) { $err = "ExitCode=$($res.ExitCode)" }
  return $false, $err
}
function Ensure-PrivateSource {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [string]$Name,
    [string]$Url,
    [string]$Type,
    [switch]$DoIt
  )
  if ([string]::IsNullOrWhiteSpace($Name)) { return $false, "No private source name configured" }
  $present = $false; $detail = $null
  $present, $detail = Test-WingetSourcePresent -WingetPath $WingetPath -Name $Name
  if ($present) {
    return $true, 'Present'
  }
  if (-not $DoIt) { return $false, "Missing (no remediation). Detail: $detail" }
  if (-not (Test-WingetPrivateSourceDefinition -Url $Url -Type $Type)) {
    return $false, 'Private source must use a supported type and an absolute HTTPS endpoint path without credentials, query, or fragment components, or local, loopback, or link-local hosts. Configure authentication out of band.'
  }
  $add = Invoke-Winget -WingetPath $WingetPath -WingetArgs @(
    'source','add',
    '-n', $Name,
    '-t', $Type,
    '-a', $Url,
    '--accept-source-agreements'
  )
  if ($add.ExitCode -eq 0) { return $true, "Added" }
  $txt = (($add.StdErr + ' ' + $add.StdOut).Trim())
  if (-not $txt) { $txt = "ExitCode=$($add.ExitCode)" }
  return $false, "Add failed: $txt"
}
# ---------------- Main ----------------
$script:Findings = Get-FindingsList
$records = New-Object System.Collections.Generic.List[object]
# Settings with sane defaults when config missing:
# - VC++ install paths are optional; remediation will log a clear error if missing.
# - Private source stays policy-driven by RequirePrivateSource + parameter overrides.
$cfgLoaded = $false
$vcX64Path = $InstallerX64Path
$vcX86Path = $InstallerX86Path
$vcArgs    = $DefaultVcArgs
$privName  = $PrivateSourceName
$privUrl   = $PrivateSourceUrl
$privType  = $DefaultPrivateSourceType
$wg = $null
$wingetVersionRaw = $null
$supportAcceptForSourceUpdate = $false
try {
  # Do not fail the run if event source registration isn't possible (commonly needs admin).
  try {
    if (-not (Ensure-EventSource -Source $EventSource -LogName $EventLogName)) {
      Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
    }
  } catch {
    Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
  }
  $cfg = Get-Config -Path $ConfigPath
  if ($cfg) {
    $cfgLoaded = $true
    if (-not $Remediate -and -not $privName) {
      $tmp = Get-NestedPropValue -Object $cfg -Path @('Winget','PrivateSourceName')
      if ($tmp) { $privName = [string]$tmp }
    }
  }
  $configStatus = 'Warning'
  $configMsg = 'Not loaded. Using defaults/parameters.'
  if ($cfgLoaded) { $configStatus = 'OK'; $configMsg = 'Loaded (path redacted).' }
  Add-Record -List $records -Record (Get-CheckRecord -Name 'Config' -Status $configStatus -Message $configMsg -Data @{
    ConfigPath = $(if ($ConfigPath) { '[configured path]' } else { '[not configured]' })
    RequirePrivateSource = $RequirePrivateSource
  })
  $wg = Resolve-WingetPath
  if (-not $wg) {
    Add-Record -List $records -Record (Get-CheckRecord -Name 'WinGet' -Status 'Error' -Message 'winget.exe not found.')
  } else {
    $env:WINGET_SUPPRESS_PROMPT = "1"
  $verRes = Invoke-Winget -WingetPath $wg -WingetArgs @('--version')
    $v = Parse-Version $verRes.StdOut
    $wingetVersionRaw = ($verRes.StdOut.Trim())
    if ($verRes.ExitCode -ne 0 -or -not $v) {
      Add-Record -List $records -Record (Get-CheckRecord -Name 'WinGet' -Status 'Error' -Message 'Version check failed.' -Data @{
        ExitCode = $verRes.ExitCode; StdErr = $verRes.StdErr.Trim(); StdOut = $verRes.StdOut.Trim()
      })
    } elseif (-not (Is-Version-AtLeast -v $v -maj $MinWingetVersionMajor -min $MinWingetVersionMinor -pat $MinWingetVersionPatch)) {
      Add-Record -List $records -Record (Get-CheckRecord -Name 'WinGet' -Status 'Error' -Message 'Version too old.' -Data @{
        Have = $v.Raw; Need = "$MinWingetVersionMajor.$MinWingetVersionMinor.$MinWingetVersionPatch"
      })
    } else {
      Add-Record -List $records -Record (Get-CheckRecord -Name 'WinGet' -Status 'OK' -Message 'OK.' -Data @{
        Version = $v.Raw; Path = $wg
      })
      [void](Add-Finding -FindingList $script:Findings -Code 'Winget-Found' -Severity 'Low' -Message "WinGet version $($v.Raw) located at $wg")
    }
    $supportAcceptForSourceUpdate = Test-WingetSupportsAcceptSourceAgreements -WingetPath $wg
    Add-Record -List $records -Record (Get-CheckRecord -Name 'WinGetSourceUpdateCapabilities' -Status 'OK' -Message 'Capability probe done.' -Data @{
      AcceptSourceAgreementsForSourceUpdate = $supportAcceptForSourceUpdate
    })
  }
  $vcx64 = $false; $vcx64v = $null
  $vcx64, $vcx64v = Test-VcRedistInstalled -Arch 'x64'
  if (-not $vcx64) {
    Add-Record -List $records -Record (Get-CheckRecord -Name 'VcRedistX64' -Status 'Error' -Message 'Missing.')
    if ($Remediate) {
      if ($vcX64Path) {
        $r = $false; $m = $null
        $r, $m = Install-VcRedist -Path $vcX64Path -InstallArgs $vcArgs -Architecture x64
        $st = 'Error'; $ms = 'Install failed.'
        if ($m -eq 'Skipped by ShouldProcess') { $st = 'Skipped'; $ms = $m }
        elseif ($r) { $st = 'OK'; $ms = 'Installed.' }
        Add-Record -List $records -Record (Get-CheckRecord -Name 'VcRedistX64Remediation' -Status $st -Message $ms -Data @{
          Detail = $m; InstallerPath = $vcX64Path
        })
      } else {
        Add-Record -List $records -Record (Get-CheckRecord -Name 'VcRedistX64Remediation' -Status 'Error' -Message 'Remediation requested but installer path not configured.')
      }
    }
  } else {
    Add-Record -List $records -Record (Get-CheckRecord -Name 'VcRedistX64' -Status 'OK' -Message 'OK.' -Data @{ Version = $vcx64v })
  }
  $vcx86 = $false; $vcx86v = $null
  $vcx86, $vcx86v = Test-VcRedistInstalled -Arch 'x86'
  if ($vcx86) {
    Add-Record -List $records -Record (Get-CheckRecord -Name 'VcRedistX86' -Status 'OK' -Message 'OK.' -Data @{ Version = $vcx86v })
  } else {
    Add-Record -List $records -Record (Get-CheckRecord -Name 'VcRedistX86' -Status 'Warning' -Message 'Not installed (optional).')
    if ($Remediate -and $vcX86Path) {
      $r = $false; $m = $null
      $r, $m = Install-VcRedist -Path $vcX86Path -InstallArgs $vcArgs -Architecture x86
      $st = 'Error'; $ms = 'Install failed.'
      if ($m -eq 'Skipped by ShouldProcess') { $st = 'Skipped'; $ms = $m }
      elseif ($r) { $st = 'OK'; $ms = 'Installed.' }
      Add-Record -List $records -Record (Get-CheckRecord -Name 'VcRedistX86Remediation' -Status $st -Message $ms -Data @{
        Detail = $m; InstallerPath = $vcX86Path
      })
    }
  }
  if ($RequirePrivateSource) {
    if (-not $wg) {
      Add-Record -List $records -Record (Get-CheckRecord -Name 'PrivateSource' -Status 'Error' -Message 'Skipped (winget missing).')
    } else {
      $havePriv = $false; $privMsg = $null
      $sourceMutationAuthorized = $Remediate -and
        $PSBoundParameters.ContainsKey('PrivateSourceName') -and
        $PSBoundParameters.ContainsKey('PrivateSourceUrl') -and
        $PSCmdlet.ShouldProcess("WinGet source '$privName'", 'Add the source if it is missing')
      $havePriv, $privMsg = Ensure-PrivateSource -WingetPath $wg -Name $privName -Url $privUrl -Type $privType -DoIt:$sourceMutationAuthorized
      $st = 'Error'
      if ($havePriv) { $st = 'OK' }
      Add-Record -List $records -Record (Get-CheckRecord -Name 'PrivateSource' -Status $st -Message $privMsg -Data (Get-PrivateSourceResultMetadata -Name $privName -Type $privType))
    }
  } else {
    Add-Record -List $records -Record (Get-CheckRecord -Name 'PrivateSource' -Status 'Skipped' -Message 'Not required.')
  }
  if ($wg -and $Remediate) {
    if (-not $PSCmdlet.ShouldProcess('WinGet sources', 'Refresh source metadata')) {
      Add-Record -List $records -Record (Get-CheckRecord -Name 'SourceUpdate' -Status 'Skipped' -Message 'Skipped by ShouldProcess.')
    } else {
      $upd = Invoke-WingetSourceUpdate -WingetPath $wg -SupportAcceptSourceAgreements:$supportAcceptForSourceUpdate
      if ($upd.ExitCode -eq 0) {
        Add-Record -List $records -Record (Get-CheckRecord -Name 'SourceUpdate' -Status 'OK' -Message 'OK.')
      } else {
        $hex = Convert-ExitCodeToHex32 -ExitCode $upd.ExitCode
        $diag = $null
        if ($DiagnoseWingetErrors) { $diag = Get-WingetErrorText -WingetPath $wg -ExitCode $upd.ExitCode }
        $st = 'Warning'
        if ($FailOnSourceUpdateError) { $st = 'Error' }
        Add-Record -List $records -Record (Get-CheckRecord -Name 'SourceUpdate' -Status $st -Message 'Failed.' -Data @{
          ExitCode = $upd.ExitCode
          ExitCodeHex = $hex
          StdErr = $upd.StdErr.Trim()
          StdOut = $upd.StdOut.Trim()
          WingetError = $diag
          Args = ($upd.Args -join ' ')
        })
      }
    }
  } elseif (-not $wg) {
    Add-Record -List $records -Record (Get-CheckRecord -Name 'SourceUpdate' -Status 'Skipped' -Message 'Skipped (winget missing).')
  } else {
    Add-Record -List $records -Record (Get-CheckRecord -Name 'SourceUpdate' -Status 'Skipped' -Message 'Skipped (audit mode).')
  }
} catch {
  Add-Record -List $records -Record (Get-CheckRecord -Name 'UnhandledException' -Status 'Error' -Message $_.Exception.Message -Data @{
    Position = (Get-TextOrEmpty $_.InvocationInfo.PositionMessage)
  })
} finally {
  if ($records.Count -eq 0) {
    Add-Record -List $records -Record (Get-CheckRecord -Name 'Runtime' -Status 'Error' -Message 'No records were produced (early termination).')
  }
  $overallOk = Get-OverallOk -Records $records.ToArray()
  # ---- Event log ----
  $eventLines = New-Object System.Collections.Generic.List[string]
  foreach ($r in $records) {
    $msg = Get-TextOrEmpty $r.Message
    [void]$eventLines.Add(("[{0}] {1}: {2}" -f $r.Status, $r.Name, $msg))
  }
  $eventMsg = ($eventLines.ToArray() -join "`r`n")
  $eventId = 4110
  $eventLevel = 'Warning'
  if ($overallOk) { $eventId = 4100; $eventLevel = 'Information' }
  Write-HealthEvent -Id $eventId -Msg $eventMsg -Level $eventLevel -Source $EventSource -LogName $EventLogName
  # ---- Formatted console output ----
  Write-ConsoleHeader -Title 'WinGet Self-Heal Summary'
  $statusText = 'NOT OK'
  $statusColor = 'Red'
  if ($overallOk) { $statusText = 'OK'; $statusColor = 'Green' }
  Write-KeyValue -Key 'Status' -Value $statusText -ValueColor $statusColor
  Write-KeyValue -Key 'Remediate' -Value ($(if ($Remediate) { 'Yes' } else { 'No' })) -ValueColor ($(if ($Remediate) { 'Yellow' } else { 'Gray' }))
  Write-KeyValue -Key 'RequirePrivateSource' -Value ([string]$RequirePrivateSource) -ValueColor ($(if ($RequirePrivateSource) { 'Yellow' } else { 'Gray' }))
  Write-KeyValue -Key 'ConfigPath' -Value $(if ($ConfigPath) { '[configured path]' } else { '[not configured]' }) -ValueColor 'Gray'
  if ($wingetVersionRaw) { Write-KeyValue -Key 'WinGetVersion' -Value $wingetVersionRaw -ValueColor 'White' }
  if (-not $script:NoConsole) {
    Write-UiLine ""
    Write-UiLine "Checks:" -ForegroundColor Cyan
    foreach ($r in $records) {
      $c = Get-StatusColor -Status $r.Status
      $msg = Get-TextOrEmpty $r.Message
      Write-UiLine ("- {0,-32} {1,-8} {2}" -f $r.Name, $r.Status, $msg) -ForegroundColor $c
    }
  }
  # V2 output contract
  $hasWarningRecords = @($records.ToArray() | Where-Object { $_.Status -eq 'Warning' }).Count -gt 0
  $resultToken = if (-not $overallOk) { 'FAIL' } elseif ($hasWarningRecords -or $script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
  $v2Summary = [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Mode = $Mode; OverallOk = $overallOk; Timestamp = Get-Date }
  $v2Result = Get-V2ResultObject -ScriptName '08-WinGet-SelfHeal.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings.ToArray()) -Summary $v2Summary -Metadata @{ Records = $records.ToArray() }
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit (Get-V2ExitCode -Result $resultToken)
}
