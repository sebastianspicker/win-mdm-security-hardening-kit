#Requires -RunAsAdministrator
#requires -version 5.1
<#
.SYNOPSIS
Triggers certificate autoenrollment, queries AutoEnrollment-related events, and reports expiring machine certificates.

.DESCRIPTION
Output model (best practice):
- Pipeline output: structured object(s) only (PSCustomObject) unless -Quiet is used.
- Console output: formatted summary via Write-UiLine only, with no text written to the pipeline.

.PARAMETER WarnDays
Certificates expiring within <= WarnDays are reported.

.PARAMETER HoursBack
How far back to query event logs.

.PARAMETER ExportPath
Optional base file path for CSV export (suffixes _summary/_events/_expiring are appended).

.PARAMETER ConfigPath
Optional JSON config path supplied with $ConfigPath. If missing or invalid, built-in defaults are used.

.PARAMETER IncludeExpired
Include already expired certificates.

.PARAMETER RequirePrivateKey
Only report certificates that have a private key (recommended).

.PARAMETER NoPulse
Skip 'certutil -pulse' (read-only health check mode).

.PARAMETER NoConsoleSummary
Do not print the console summary block.

.PARAMETER Quiet
Do not write the result object to the success output stream (console summary still shown unless suppressed).

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

.PARAMETER NoColor
  Disable colored output.


.OUTPUTS
  None by default.
  When -PassThru is used, emits a PSCustomObject v2 result with Script, Mode, Result, Findings, Summary, and Metadata properties.

.EXAMPLE
  .\24-Cert-AutoEnrollment-Health.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateRange(1, 3650)]
  [int]$WarnDays = 30,

  [ValidateRange(1, 168)]
  [int]$HoursBack = 24,

  [string]$ExportPath,

  [string]$ConfigPath,

  [switch]$IncludeExpired,

  [bool]$RequirePrivateKey = $true,

  [switch]$NoPulse,

  [switch]$NoConsoleSummary,

  [switch]$Quiet

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'JsonCatalog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '24-Cert-AutoEnrollment-Health.ps1' -BoundParameters $PSBoundParameters `
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
  $result = Get-V2ResultObject -ScriptName '24-Cert-AutoEnrollment-Health.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$script:Findings = Get-FindingsList

function Get-ConfigValueInt {
  param(
    $ConfigObject,
    [string]$Name,
    [int]$DefaultValue,
    [int]$Min,
    [int]$Max
  )

  if ($null -eq $ConfigObject) { return $DefaultValue }

  $val = $null
  try { $val = $ConfigObject.$Name } catch { $val = $null }
  if ($null -eq $val) { return $DefaultValue }

  $intVal = $null
  if ([int]::TryParse([string]$val, [ref]$intVal)) {
    if ($intVal -lt $Min) { return $Min }
    if ($intVal -gt $Max) { return $Max }
    return $intVal
  }

  $DefaultValue
}

function Get-ConfigValueString {
  param(
    $ConfigObject,
    [string]$Name,
    [string]$DefaultValue
  )

  if ($null -eq $ConfigObject) { return $DefaultValue }

  $val = $null
  try { $val = $ConfigObject.$Name } catch { $val = $null }
  if ([string]::IsNullOrWhiteSpace([string]$val)) { return $DefaultValue }
  [string]$val
}

function Get-ConfigValueBool {
  param(
    $ConfigObject,
    [string]$Name,
    [bool]$DefaultValue
  )

  if ($null -eq $ConfigObject) { return $DefaultValue }

  $val = $null
  try { $val = $ConfigObject.$Name } catch { $val = $null }
  if ($null -eq $val) { return $DefaultValue }

  if ($val -is [bool]) { return [bool]$val }

  $s = ([string]$val).Trim()
  switch -Regex ($s.ToLowerInvariant()) {
    '^(1|true|yes|y)$' { $true; break }
    '^(0|false|no|n)$' { $false; break }
    default { $DefaultValue; break }
  }
}

function Get-AutoEnrollEvents {
  param(
    [Parameter(Mandatory)][DateTime]$StartTime,
    [Parameter(Mandatory)][string]$OperationalLogName
  )

  $out = [pscustomobject]@{
    Mode                 = $null
    LogNameUsed          = $null
    OperationalAvailable = $true
    Error                = $null
    Events               = @()
  }

  try {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = $OperationalLogName; StartTime = $StartTime } -ErrorAction Stop
    $out.Mode = 'Operational'
    $out.LogNameUsed = $OperationalLogName
    $out.Events = $ev
    return $out
  } catch {
    $out.OperationalAvailable = $false
    $out.Error = $_.Exception.Message
  }

  try {
    $providers = @(
      'Microsoft-Windows-CertificateServicesClient-AutoEnrollment',
      'Microsoft-Windows-CertificateServicesClient-CertEnroll',
      'Microsoft-Windows-CertificateServicesClient'
    )

    $evAll = @()
    foreach ($p in $providers) {
      try {
        $evAll += Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $p; StartTime = $StartTime } -ErrorAction Stop
      } catch {
        Write-Verbose ("Certificate auto-enrollment event provider query failed for '{0}': {1}" -f $p,$_.Exception.Message)
      }
    }

    $out.Mode = 'ApplicationFallback'
    $out.LogNameUsed = 'Application'
    $out.Events = $evAll
    return $out
  } catch {
    $out.Mode = 'None'
    $out.LogNameUsed = $null
    $out.Events = @()
    if ($out.Error) { $out.Error = $out.Error + " | Fallback failed: " + $_.Exception.Message }
    else { $out.Error = $_.Exception.Message }
    return $out
  }
}

function Get-HealthStatus {
  param([Parameter(Mandatory)]$ResultObject)

  if ($ResultObject.CertificateReadError) { return 'Error' }
  if ($ResultObject.EventQueryMode -eq 'None') { return 'Error' }
  if (-not $ResultObject.NoPulse -and -not $ResultObject.AutoEnrollmentTriggered) { return 'Warning' }
  if ($ResultObject.ExpiringCertsFound -gt 0) { return 'Warning' }

  'OK'
}


function Show-ConsoleSummary {
  param([Parameter(Mandatory)]$ResultObject)

  $status = Get-HealthStatus -ResultObject $ResultObject

  $statusColor = 'Green'
  if ($status -eq 'Warning') { $statusColor = 'Yellow' }
  if ($status -eq 'Error')   { $statusColor = 'Red' }

  $headline = "Certificate AutoEnrollment Health"
  $line = ('=' * ($headline.Length + 10))

  Write-UiLine ""
  Write-UiLine $line -ForegroundColor DarkGray
  Write-UiLine ("===  {0}  ===" -f $headline) -ForegroundColor Cyan
  Write-UiLine $line -ForegroundColor DarkGray

  Write-KeyValue -Label 'Status' -Value $status -LabelColor Gray -ValueColor $statusColor
  Write-KeyValue -Label 'ComputerName' -Value $ResultObject.ComputerName -LabelColor Gray -ValueColor White
  Write-KeyValue -Label 'Timestamp' -Value ([string]$ResultObject.Timestamp) -LabelColor Gray -ValueColor White

  Write-UiLine ""
  Write-UiLine "Configuration" -ForegroundColor Cyan
  Write-UiLine ('-' * 40) -ForegroundColor DarkGray

  $cfgLoadedColor = 'Warning'
  if ($ResultObject.ConfigLoaded) { $cfgLoadedColor = 'Green' }
  Write-KeyValue -Label 'ConfigLoaded' -Value ([string]$ResultObject.ConfigLoaded) -ValueColor $cfgLoadedColor

  if ($ResultObject.ConfigPath) {
    Write-KeyValue -Label 'ConfigPath' -Value $ResultObject.ConfigPath -ValueColor DarkGray
  }

  Write-UiLine ""
  Write-UiLine "AutoEnrollment" -ForegroundColor Cyan
  Write-UiLine ('-' * 40) -ForegroundColor DarkGray

  if ($ResultObject.NoPulse) {
    Write-KeyValue -Label 'Pulse' -Value 'Skipped (NoPulse)' -ValueColor DarkGray
  } else {
    $pulseColor = 'Red'
    if ($ResultObject.AutoEnrollmentTriggered) { $pulseColor = 'Green' }
    Write-KeyValue -Label 'PulseTriggered' -Value ([string]$ResultObject.AutoEnrollmentTriggered) -ValueColor $pulseColor

    if ($ResultObject.AutoEnrollmentError) {
      Write-KeyValue -Label 'PulseError' -Value $ResultObject.AutoEnrollmentError -ValueColor Red
    }
  }

  Write-UiLine ""
  Write-UiLine "Event Log" -ForegroundColor Cyan
  Write-UiLine ('-' * 40) -ForegroundColor DarkGray

  $modeColor = 'Warning'
  if ($ResultObject.EventQueryMode -eq 'Operational') { $modeColor = 'Green' }
  if ($ResultObject.EventQueryMode -eq 'None') { $modeColor = 'Red' }
  Write-KeyValue -Label 'QueryMode' -Value $ResultObject.EventQueryMode -ValueColor $modeColor

  Write-KeyValue -Label 'LogNameUsed' -Value ([string]$ResultObject.LogNameUsed) -ValueColor White
  Write-KeyValue -Label 'HoursBack' -Value ([string]$ResultObject.HoursBack) -ValueColor White

  $eventsColor = 'Gray'
  if ($ResultObject.EventsFound -gt 0) { $eventsColor = 'Warning' }
  Write-KeyValue -Label 'EventsFound' -Value ([string]$ResultObject.EventsFound) -ValueColor $eventsColor

  if ($ResultObject.EventQueryError) {
    Write-KeyValue -Label 'EventQueryError' -Value $ResultObject.EventQueryError -ValueColor DarkYellow
  }

  Write-UiLine ""
  Write-UiLine "Certificates (LocalMachine\\My)" -ForegroundColor Cyan
  Write-UiLine ('-' * 40) -ForegroundColor DarkGray

  Write-KeyValue -Label 'WarnDays' -Value ([string]$ResultObject.WarnDays) -ValueColor White
  Write-KeyValue -Label 'IncludeExpired' -Value ([string]$ResultObject.IncludeExpired) -ValueColor White
  Write-KeyValue -Label 'RequirePrivateKey' -Value ([string]$ResultObject.RequirePrivateKey) -ValueColor White

  $expColor = 'Green'
  if ($ResultObject.ExpiringCertsFound -gt 0) { $expColor = 'Yellow' }
  Write-KeyValue -Label 'ExpiringCertsFound' -Value ([string]$ResultObject.ExpiringCertsFound) -ValueColor $expColor

  if ($ResultObject.CertificateReadError) {
    Write-KeyValue -Label 'CertificateReadError' -Value $ResultObject.CertificateReadError -ValueColor Red
  }

  Write-UiLine ""
  Write-UiLine "Export" -ForegroundColor Cyan
  Write-UiLine ('-' * 40) -ForegroundColor DarkGray

  if ($ResultObject.ExportBasePath) {
    Write-KeyValue -Label 'CSV Export' -Value 'Enabled' -ValueColor Green
    Write-KeyValue -Label 'ExportBasePath' -Value $ResultObject.ExportBasePath -ValueColor White
  } else {
    Write-KeyValue -Label 'CSV Export' -Value 'Disabled' -ValueColor DarkGray
  }

  Write-UiLine $line -ForegroundColor DarkGray
  Write-UiLine ""
}

# Defaults + optional JSON config
$defaults = [pscustomobject]@{
  WarnDays          = 30
  HoursBack         = 24
  RequirePrivateKey = $true
  IncludeExpired    = $false
  ExportPath        = $null
  LogName           = 'Microsoft-Windows-CertificateServicesClient-AutoEnrollment/Operational'
}

$configObj = Read-JsonFileSafe -Path $ConfigPath

$WarnDays  = Get-ConfigValueInt -ConfigObject $configObj -Name 'WarnDays'  -DefaultValue $WarnDays  -Min 1 -Max 3650
$HoursBack = Get-ConfigValueInt -ConfigObject $configObj -Name 'HoursBack' -DefaultValue $HoursBack -Min 1 -Max 168

if (-not $PSBoundParameters.ContainsKey('RequirePrivateKey')) {
  $RequirePrivateKey = Get-ConfigValueBool -ConfigObject $configObj -Name 'RequirePrivateKey' -DefaultValue $defaults.RequirePrivateKey
}
if (-not $PSBoundParameters.ContainsKey('IncludeExpired')) {
  $IncludeExpired = Get-ConfigValueBool -ConfigObject $configObj -Name 'IncludeExpired' -DefaultValue $defaults.IncludeExpired
}
if (-not $PSBoundParameters.ContainsKey('ExportPath')) {
  $ExportPath = Get-ConfigValueString -ConfigObject $configObj -Name 'ExportPath' -DefaultValue $defaults.ExportPath
}

$logName = Get-ConfigValueString -ConfigObject $configObj -Name 'LogName' -DefaultValue $defaults.LogName

# Preconditions
Require-Admin

if (-not (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)) {
  $msg = "Cert: drive is not available. The Microsoft.PowerShell.Security provider/module may be missing."
  Write-Warning $msg
  $v2Result = Get-V2ResultObject -ScriptName '24-Cert-AutoEnrollment-Health.ps1' -Mode $Mode -Result 'FAIL' -Findings @() -Summary @{ Error = $msg } -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit (Get-V2ExitCode -Result 'FAIL')
}

# 1) Trigger autoenrollment (optional)
$autoEnrollTriggered = $false
$autoEnrollError     = $null

if ($NoPulse) {
  $autoEnrollTriggered = $false
  $autoEnrollError = "Skipped (NoPulse)."
} else {
  try {
    $pulse = Invoke-NativeCommand -Command 'certutil.exe' -Arguments @('-pulse') -CaptureOutput -Quiet -TimeoutSeconds 120 -MaxOutputBytes 262144
    if ($null -eq $pulse -or -not $pulse.Success -or $pulse.TimedOut -or $pulse.OutputTruncated -or $pulse.StderrTruncated) { throw 'certutil -pulse timed out, failed, or produced truncated output.' }
    $autoEnrollTriggered = $true
  } catch {
    $autoEnrollTriggered = $false
    $autoEnrollError     = $_.Exception.Message
  }
}

# 2) Query events
$startTime = (Get-Date).AddHours(-1 * $HoursBack)

$eventQuery = Get-AutoEnrollEvents -StartTime $startTime -OperationalLogName $logName

$eventsRaw = @($eventQuery.Events)
$eventOut = $eventsRaw | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message

# 3) Expiring machine certificates
$now      = Get-Date
$deadline = (Get-Date).AddDays($WarnDays)

$certReadError = $null
$certOut = @()

try {
  $certCandidates = Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop

  if ($RequirePrivateKey) {
    $certCandidates = $certCandidates | Where-Object { $_.HasPrivateKey }
  }

  $certCandidates = $certCandidates | Where-Object {
    if ($IncludeExpired) { $_.NotAfter -le $deadline }
    else { ($_.NotAfter -ge $now) -and ($_.NotAfter -le $deadline) }
  }

  $certOut = $certCandidates | Select-Object Subject, Thumbprint, NotAfter, Issuer, FriendlyName, HasPrivateKey
} catch {
  $certOut = @()
  $certReadError = $_.Exception.Message
}

# 4) Unified result object
$result = [pscustomobject]@{
  ComputerName              = $env:COMPUTERNAME
  Timestamp                 = Get-Date

  WarnDays                  = $WarnDays
  HoursBack                 = $HoursBack
  IncludeExpired            = [bool]$IncludeExpired
  RequirePrivateKey         = [bool]$RequirePrivateKey
  NoPulse                   = [bool]$NoPulse

  ConfigPath                = $ConfigPath
  ConfigLoaded              = ($null -ne $configObj)

  AutoEnrollmentTriggered   = $autoEnrollTriggered
  AutoEnrollmentError       = $autoEnrollError

  EventQueryMode            = $eventQuery.Mode
  AutoEnrollmentLogName     = $logName
  LogNameUsed               = $eventQuery.LogNameUsed
  OperationalLogAvailable   = [bool]$eventQuery.OperationalAvailable
  EventQueryError           = $eventQuery.Error
  EventsFound               = @($eventOut).Count

  ExpiringCertsFound        = @($certOut).Count
  CertificateReadError      = $certReadError

  ExportBasePath            = $ExportPath

  Events                    = $eventOut
  ExpiringCertificates      = $certOut
}

if ($certReadError) {
  Add-Finding -FindingList $script:Findings -Code 'CERT-ReadError' -Severity 'High' `
    -Message ("Certificate read error: {0}" -f $certReadError)
}
if ($eventQuery.Mode -eq 'None') {
  Add-Finding -FindingList $script:Findings -Code 'CERT-EventQueryFailed' -Severity 'Medium' `
    -Message ("Event log query failed: {0}" -f $eventQuery.Error)
}
if (-not $NoPulse -and -not $autoEnrollTriggered) {
  Add-Finding -FindingList $script:Findings -Code 'CERT-PulseFailed' -Severity 'Medium' `
    -Message ("AutoEnrollment pulse failed: {0}" -f $autoEnrollError)
}
foreach ($cert in @($certOut)) {
  $daysLeft = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays, 0)
  $sev = if ($daysLeft -le 7) { 'High' } elseif ($daysLeft -le 14) { 'Medium' } else { 'Low' }
  Add-Finding -FindingList $script:Findings -Code 'CERT-Expiring' -Severity $sev `
    -Message ("Certificate expiring in {0} days: {1} (Thumbprint: {2})" -f $daysLeft, $cert.Subject, $cert.Thumbprint) `
    -Extra @{ Subject = $cert.Subject; Thumbprint = $cert.Thumbprint; NotAfter = $cert.NotAfter; DaysLeft = $daysLeft }
}

# 5) Optional CSV export
if ($ExportPath) {
  $folder = Split-Path -Path $ExportPath -Parent
  if (-not $folder) { $folder = (Get-Location).Path }
  [void](Ensure-Directory -Path $folder)

  $base = [IO.Path]::GetFileNameWithoutExtension($ExportPath)

  $summaryPath = Join-Path $folder ($base + "_summary.csv")
  $eventsPath  = Join-Path $folder ($base + "_events.csv")
  $certsPath   = Join-Path $folder ($base + "_expiring.csv")

  $result |
    Select-Object ComputerName, Timestamp, WarnDays, HoursBack, IncludeExpired, RequirePrivateKey, NoPulse,
                  ConfigPath, ConfigLoaded,
                  AutoEnrollmentTriggered, AutoEnrollmentError,
                  EventQueryMode, AutoEnrollmentLogName, LogNameUsed, OperationalLogAvailable, EventQueryError, EventsFound,
                  ExpiringCertsFound, CertificateReadError, ExportBasePath |
    Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8

  $eventOut | Export-Csv -Path $eventsPath -NoTypeInformation -Encoding UTF8
  $certOut  | Export-Csv -Path $certsPath  -NoTypeInformation -Encoding UTF8
}

# Console summary (host-only)
if (-not $NoConsoleSummary) {
  Show-ConsoleSummary -ResultObject $result
}

# V2 output contract
$resultToken = if ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '24-Cert-AutoEnrollment-Health.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $result -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
