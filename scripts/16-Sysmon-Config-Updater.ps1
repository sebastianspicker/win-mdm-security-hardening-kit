#requires -version 5.1
<#
.SYNOPSIS
  Applies a desired Sysmon configuration in an idempotent, auditable way and reports drift/compliance.
.DESCRIPTION
  This script selects a target Sysmon XML configuration, validates it, compares it to the last known applied state and the current runtime configuration, and optionally remediates drift by installing/updating Sysmon.
  It supports three configuration source modes:
  - Direct file mode: use -ConfigPath to point to a specific XML file.
  - Directory mode: use -SourceDir to pick a suitable XML from a folder (optionally filtered with -ConfigNameHint).
  - Manifest mode: use -ManifestPath to load JSON settings (optional allowlist + min engine) and optionally pick a config file named by the manifest.
  Validation and decision logic:
  - Validates that the XML is well-formed and has a Sysmon root element.
  - Optionally enforces a SHA256 allowlist if provided by the manifest.
  - Optionally enforces a minimum Sysmon engine version if provided by the manifest or -MinEngine.
  - Detects drift using:
    - The desired config file SHA256 vs. the previously recorded desired SHA256 in the state file.
    - A hash of the current runtime config dump (Sysmon "-c" without a file) vs. the previously recorded runtime dump hash.
  Remediation behavior:
  - If -Mode Remediate is set and Sysmon is not installed, the script installs Sysmon using the selected XML.
  - If -Mode Remediate is set and drift is detected, the script updates Sysmon to use the selected XML.
  - If -Mode Audit is used, the script runs in audit mode and returns a non-OK status when drift/non-compliance is detected.
  Optional logging channel management:
  - If -EnsureChannel is set, the script checks whether the Sysmon Operational channel is enabled and whether its maximum size meets the requested value.
  - If -EnsureChannel is set together with -Mode Remediate, the script attempts to enable/resize the channel to become compliant.
  State and output:
  - Writes a state JSON that records what was applied/observed (host, time, sysmon engine details, desired config SHA256, source, runtime dump hash).
  - Emits a structured summary object to the pipeline (suitable for Export-Csv / ConvertTo-Json / Where-Object).
  - Writes a human-readable console summary at the end (can be disabled).
.PARAMETER ConfigPath
  Path to a Sysmon configuration XML file to apply/audit.
.PARAMETER SourceDir
  Directory containing one or more Sysmon configuration XML files.
  The script selects one file (optionally filtered by -ConfigNameHint, otherwise picks the "best" candidate based on naming/version hint and timestamps).
.PARAMETER ManifestPath
  Path to a manifest JSON file that can define:
  - Config.File: Preferred XML file name to select (typically relative to -SourceDir).
  - AllowedHashes: Array of allowed SHA256 hashes for the selected XML file.
  - MinEngine: Minimum Sysmon engine version required.
.PARAMETER SysmonExePath
  Optional explicit path to sysmon.exe/sysmon64.exe.
  If not provided, the script attempts to discover the Sysmon executable from the installed service configuration or known default locations.
.PARAMETER Mode
  Execution mode:
  - Audit: report drift/non-compliance without changing the system.
  - Remediate: perform changes to reach the desired state (install/update Sysmon config; optionally enable/resize channel when -EnsureChannel is used).
.PARAMETER EnsureChannel
  If set, validates the Sysmon Operational channel status (enabled + minimum size).
  Use together with -Mode Remediate to enforce the desired channel settings.
.PARAMETER ChannelSizeMiB
  Desired minimum maximum size of the Sysmon Operational channel in MiB.
  Only used when -EnsureChannel is set.
.PARAMETER StatePath
  Path to the state JSON file used to track last applied/observed configuration.
  If the state file is missing or invalid JSON, the script uses safe defaults and continues.
.PARAMETER ConfigPathFallback
  Optional fallback XML file path to use if selection via -ConfigPath/-SourceDir/-ManifestPath does not yield a config.
.PARAMETER MinEngine
  Optional minimum Sysmon engine version requirement (for example: "15.0").
  If not provided, the script may use MinEngine from the manifest.
.PARAMETER ConfigNameHint
  Optional regex hint used to filter XML files in -SourceDir (for example: "prod|server" or "v15").
.PARAMETER NoConsoleSummary
  If set, disables the human-readable console summary.
  The structured pipeline output is still produced.
.PARAMETER SanitizeConsoleOutput
  If set, the console summary masks local/UNC paths (helpful when pasting console output into tickets or GitHub issues).
  This does not change the structured pipeline output.
.PARAMETER NoColor
  If set, disables colored console output.
.INPUTS
  None. This script does not accept pipeline input.
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
  System.Management.Automation.PSCustomObject.
  The script outputs exactly one structured summary object with fields such as:
  - Ok, DriftDetected, Remediate, EnsureChannel, IsAdmin
  - ConfigFile, DesiredSha256, PrevDesiredSha256
  - SysmonService, SysmonExe, EngineVersion, MinEngineRequired
  - CurrentDumpSha256, InstalledNow, StateWritten
  - Actions (string[]), Warnings (string[])
.EXAMPLE
  # Audit a specific config file (no changes)
  .\16-Sysmon-Config-Updater.ps1 -ConfigPath $ConfigPath
.EXAMPLE
  # Remediate: apply the config if drift is detected (or install if missing)
  .\16-Sysmon-Config-Updater.ps1 -ConfigPath $ConfigPath -Mode Remediate
.EXAMPLE
  # Select config from a directory using a name hint, audit-only
  .\16-Sysmon-Config-Updater.ps1 -SourceDir $SourceDir -ConfigNameHint "prod"
.EXAMPLE
  # Use a manifest and a directory (manifest may specify Config.File, AllowedHashes, MinEngine)
  .\16-Sysmon-Config-Updater.ps1 -ManifestPath $ManifestPath -SourceDir $SourceDir -Mode Remediate
.EXAMPLE
  # Enforce Sysmon Operational channel settings during remediation
  .\16-Sysmon-Config-Updater.ps1 -ConfigPath $ConfigPath -EnsureChannel -ChannelSizeMiB 256 -Mode Remediate
.EXAMPLE
  # Export the structured result (pipeline-safe)
  .\16-Sysmon-Config-Updater.ps1 -ConfigPath $ConfigPath | Export-Csv -NoTypeInformation -Path $OutputPath
.NOTES
  Behavior on missing/invalid JSON:
  - An explicitly supplied manifest must exist and conform to the expected shape. Missing, invalid, or unsafe manifests block Sysmon installation and config application.
  - State: if missing/invalid, the script continues with empty defaults (drift detection may rely on runtime dump hash and current desired hash).
  Idempotency and drift:
  - In audit mode (-Mode Audit), the script reports non-OK when it detects drift or required settings are not compliant.
  - In remediate mode, the script only applies changes when drift/non-compliance is detected.
  Security considerations:
  - When using AllowedHashes, ensure the allowlist is maintained securely.
  - Running with -Mode Remediate requires administrative privileges to install/update Sysmon and to change event log channel settings.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [string]$ConfigPath,
  [string]$SourceDir,
  [string]$ManifestPath,
  [string]$SysmonExePath,
  [switch]$EnsureChannel,
  [ValidateRange(1, 4096)]
  [int]$ChannelSizeMiB = 256,
  # Optional caller input; runtime resolves a protected default state path.
  [string]$StatePath,
  [string]$ConfigPathFallback,
  [string]$MinEngine,
  [string]$ConfigNameHint,
  # Console output control (does NOT affect pipeline output)
  [switch]$NoConsoleSummary,
  # Sanitizes only console output (pipeline output remains raw/structured)
  [switch]$SanitizeConsoleOutput,
  # Console rendering preferences
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
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Evidence.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'internal/16-Sysmon-Config-Updater.helpers.ps1')
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '16-Sysmon-Config-Updater.ps1' -BoundParameters $PSBoundParameters `
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
  $result = Get-V2ResultObject -ScriptName '16-Sysmon-Config-Updater.ps1' -Mode $Mode -Result $resultToken -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $resultToken)
}

$StatePath = Get-SysmonStatePath -RequestedPath $StatePath -FileName 'config-updater-state.json'

$script:Findings = Get-FindingsList
# -----------------------------
# Main
# -----------------------------
if (-not (Ensure-EventSource)) {
  Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
}
$ok = $true
$needUpdate = $false
$installed = $false
$lines   = @()
$actions = @()
$warns   = @()
$policyBlocked = $false
$fatalError = $null
$explicitExeHint = -not [string]::IsNullOrWhiteSpace($SysmonExePath)
# Structured summary object for pipeline and console
$summary = [ordered]@{
  Ok                = $false
  Remediate         = [bool]$Remediate
  EnsureChannel     = [bool]$EnsureChannel
  IsAdmin           = $false
  ConfigFile        = $null
  DesiredSha256     = $null
  PrevDesiredSha256 = $null
  SysmonService     = $null
  SysmonExe         = $null
  EngineVersion     = $null
  MinEngineRequired = $null
  CurrentDumpSha256 = $null
  DriftDetected     = $false
  InstalledNow      = $false
  Actions           = @()
  Warnings          = @()
  StateWritten      = $false
  StatePath         = $StatePath
  PolicyBlocked     = $false
  ObservedDesiredSha256 = $null
  LastAppliedSha256 = $null
}
try {
  $isAdmin = Test-IsAdmin
  $summary.IsAdmin = $isAdmin
  # Remediation preview must not launch Sysmon or query runtime config through
  # Sysmon process execution; keep the run to validation and decision reporting.
  $previewOnly = ($Remediate -and [bool]$WhatIfPreference)
  if ($Remediate -and -not $isAdmin) {
    $ok = $false
    $warns += "Remediate requested but not elevated."
  }
  # An explicit manifest is policy input: malformed input fails closed rather
  # than silently turning off its allowlist/minimum-engine requirements.
  $manifestDefault = @{
    MinEngine     = $null
    AllowedHashes = @()
    Config        = @{ File = $null }
  }
  $manifest = $manifestDefault
  if ($ManifestPath) {
    $manifestCheck = Test-ManifestPolicy -Path $ManifestPath -SourceDirectory $SourceDir
    if ($manifestCheck.Valid) {
      $manifest = $manifestCheck.Manifest
    } else {
      $policyBlocked = $true
      $ok = $false
      $warns += ('Manifest validation failed: ' + $manifestCheck.Reason)
    }
  }
  if ((-not $MinEngine) -and $manifest -and $manifest.PSObject.Properties['MinEngine'] -and $manifest.MinEngine) { $MinEngine = [string]$manifest.MinEngine }
  $summary.MinEngineRequired = $MinEngine
  $minEngVer = $null
  if ($MinEngine) { $minEngVer = Parse-Version $MinEngine }
  if ($MinEngine -and -not $minEngVer) {
    $policyBlocked = $true
    $ok = $false
    $warns += 'MinEngine must be a version string.'
  }
  $allowHashes = @()
  if ($manifest -and $manifest.PSObject.Properties['AllowedHashes'] -and $manifest.AllowedHashes) {
    $allowHashes = @($manifest.AllowedHashes | ForEach-Object { $_.ToString().ToLowerInvariant() })
  }
  # Select config file from explicit path, dir or manifest mapping
  $cfgFile = Select-ConfigFile -Path $ConfigPath -Dir $SourceDir -NameHint $ConfigNameHint -Manifest $manifest
  if (-not $cfgFile -and $ConfigPathFallback -and (Test-Path -LiteralPath $ConfigPathFallback)) {
    $cfgFile = Get-Item -LiteralPath $ConfigPathFallback
  }
  if (-not $cfgFile) {
    throw "No config file found. Use -ConfigPath, -SourceDir or -ManifestPath."
  }
  $cfgPath = $cfgFile.FullName
  $summary.ConfigFile = $cfgFile.Name
  $cfgSnapshot = Get-ConfigSnapshot -Path $cfgPath
  $cfgHash = $cfgSnapshot.Sha256
  $summary.DesiredSha256 = $cfgHash
  $summary.ObservedDesiredSha256 = $cfgHash
  $tmp = Validate-ConfigXml $cfgSnapshot.Bytes
  $valid = [bool]$tmp[0]
  $valMsg = [string]$tmp[1]
  if (-not $valid) { throw ("Config XML invalid: " + $valMsg) }
  $lines += ("Config: " + $cfgFile.Name + " (SHA256=" + $cfgHash + "; " + $valMsg + ")")
  if ($allowHashes.Count -gt 0 -and ($allowHashes -notcontains $cfgHash)) {
    $ok = $false
    $policyBlocked = $true
    $warns += "Config SHA256 not in allowlist."
  }
  # Do not probe or launch Sysmon after policy input has already blocked apply.
  $exe = $null; $svcName = $null; $eng = $null
  if (-not $policyBlocked) {
    # Detect Sysmon
    $exe = Resolve-SysmonExe -Hint $SysmonExePath
    $svcName = Get-SysmonServiceName
    # A configured minimum must be decided without executing Sysmon. If the
    # file metadata cannot establish the version, the requirement fails closed.
    $eng = Get-SysmonEngineVersion -Exe $exe
    $summary.SysmonExe = $exe
    $summary.SysmonService = $svcName
    if ($eng) { $summary.EngineVersion = $eng.Raw }
    if ($svcName) {
      $lines += ("Sysmon: Service=" + $svcName + ", Exe='" + ($(if($exe){$exe}else{'n/a'})) + "', Engine=" + ($(if($eng){$eng.Raw}else{'n/a'})))
    } else {
      $lines += ("Sysmon: Service not installed (Exe=" + ($(if($exe){$exe}else{'n/a'})) + ")")
    }
    if ($explicitExeHint -and -not $exe) {
      $ok = $false
      $policyBlocked = $true
      $warns += 'Explicit SysmonExePath did not pass trusted executable validation; service discovery fallback was refused.'
    }
    if ($exe -and -not (Test-TrustedSysmonExecutable -Path $exe)) {
      $ok = $false
      $policyBlocked = $true
      $warns += 'Sysmon executable did not pass trusted executable validation; process execution was blocked.'
    }
    if ($minEngVer -and $eng) {
      if ((Cmp-Ver $eng $minEngVer) -lt 0) {
        $ok = $false
        $policyBlocked = $true
        $warns += ("Engine below minimum: Installed=" + $eng.Raw + " Required=" + $minEngVer.Raw)
      }
    } elseif ($minEngVer -and (-not $eng)) {
      $ok = $false
      $policyBlocked = $true
      $warns += ("Cannot determine engine version; minimum required=" + $minEngVer.Raw)
    }
  }
  $summary.PolicyBlocked = [bool]$policyBlocked
  # State defaults if missing or invalid JSON
  $stateDefault = @{
    Version = 2
    Observed = @{ DesiredSha256 = $null }
    Applied = @{ Sha256 = $null }
    Runtime = @{ CurrentDumpSha256 = $null }
  }
  $state = Load-JsonOrDefault -Path $StatePath -DefaultObject $stateDefault
  $lastAppliedHash = $null
  if ($state -and $state.PSObject.Properties['Applied'] -and $state.Applied -and $state.Applied.PSObject.Properties['Sha256'] -and $state.Applied.Sha256) {
    $lastAppliedHash = [string]$state.Applied.Sha256
  } elseif ($state -and $state.PSObject.Properties['Config'] -and $state.Config -and $state.Config.PSObject.Properties['Sha256'] -and $state.Config.Sha256) {
    $warns += 'Legacy state did not distinguish observed from successfully applied configuration; forcing one safe reapply.'
  }
  $summary.PrevDesiredSha256 = $lastAppliedHash
  $summary.LastAppliedSha256 = $lastAppliedHash
  if ($lastAppliedHash -ne $cfgHash) { $needUpdate = $true }
  # Runtime dump hash (best effort)
  $currentCfgDumpSha = $null
  if ($svcName -and $exe -and -not $explicitExeHint -and -not $policyBlocked) {
    if ($previewOnly) {
      # sysmon -c can touch external process behavior; skip it in preview mode
      # so -WhatIf stays a pure planning path.
      $warns += "Runtime config dump skipped in WhatIf mode."
    } else {
      $currentCfgDumpSha = Get-SysmonCurrentConfigSha256 -Exe $exe
      $summary.CurrentDumpSha256 = $currentCfgDumpSha
      if (-not $currentCfgDumpSha) {
        $warns += "Could not compute runtime config dump hash."
      } else {
        $prevDump = $null
        if ($state -and $state.Runtime -and $state.Runtime.CurrentDumpSha256) { $prevDump = [string]$state.Runtime.CurrentDumpSha256 }
        if ($prevDump -and ($prevDump -ne $currentCfgDumpSha)) {
          $needUpdate = $true
          $warns += "Runtime drift: current dump hash differs from last recorded."
        }
      }
    }
  } elseif ($svcName -and $exe -and $explicitExeHint -and -not $policyBlocked) {
    $warns += 'Runtime config dump skipped for explicitly supplied SysmonExePath.'
  }
  # Optional channel compliance
  if ($EnsureChannel -and -not $policyBlocked) {
    $doIt = $false
    if ($Remediate -and $isAdmin) { $doIt = $true }
    $res = Ensure-SysmonChannel -DoIt:$doIt -MiB $ChannelSizeMiB -Cmdlet $PSCmdlet
    $cOk  = [bool]$res[0]
    $cMsg = [string]$res[1]
    if (-not $cOk) { $ok=$false; $warns += ("Channel not compliant: " + $cMsg) }
    else { if ($cMsg) { $actions += ("Channel: " + $cMsg) } }
  }
  # Remediation
  if ($Remediate -and $isAdmin -and -not $policyBlocked) {
    if (-not $exe -or -not (Test-TrustedSysmonExecutable -Path $exe)) {
      $ok = $false
      $policyBlocked = $true
      $summary.PolicyBlocked = $true
      $warns += 'Sysmon executable did not pass trusted executable validation.'
    }
  }
  if ($Remediate -and $isAdmin -and -not $policyBlocked) {
    if (-not $svcName) {
      if (-not $exe) { $ok=$false; throw "Sysmon not installed and SysmonExePath not provided/found." }
      try {
        # Install with config (-i) and accept EULA.
        if ($PSCmdlet.ShouldProcess($exe, "Install Sysmon with staged configuration")) {
          $stage = $null
          try {
            $stage = New-StagedConfigFile -Bytes $cfgSnapshot.Bytes
            if ((Get-BytesSha256 -Bytes $cfgSnapshot.Bytes) -ne $cfgHash) { throw 'Config snapshot hash changed before apply.' }
            $p = Invoke-StagedSysmonCommand -Exe $exe -Arguments @('-accepteula', '-i', $stage.Path)
          } finally { if ($stage) { $stage.Stream.Dispose(); Remove-Item -LiteralPath $stage.Path -Force -ErrorAction SilentlyContinue } }
          if ($p -and $p.Success -and -not $p.TimedOut -and -not $p.OutputTruncated -and -not $p.StderrTruncated) {
            $installed = $true
            $actions += "Installed Sysmon"
            $needUpdate = $false
            $lastAppliedHash = $cfgHash
            $summary.LastAppliedSha256 = $lastAppliedHash
          } else {
            $ok = $false
            $warns += ("Install failed: " + ($(if ($p -and $p.TimedOut) { 'timed out' } elseif ($p -and ($p.OutputTruncated -or $p.StderrTruncated)) { 'output was truncated' } elseif ($p) { 'exitcode=' + $p.ExitCode } else { 'native command did not return a result' })))
          }
        } else {
          $ok = $false
          $needUpdate = $true
          $warns += "Install skipped by ShouldProcess."
        }
      } catch {
        $ok = $false
        $warns += ("Install failed: " + $_.Exception.Message)
      }
    }
    elseif ($needUpdate) {
      try {
        # Update config (-c) and accept EULA.
        if ($PSCmdlet.ShouldProcess($exe, "Update Sysmon with staged configuration")) {
          $stage = $null
          try {
            $stage = New-StagedConfigFile -Bytes $cfgSnapshot.Bytes
            if ((Get-BytesSha256 -Bytes $cfgSnapshot.Bytes) -ne $cfgHash) { throw 'Config snapshot hash changed before apply.' }
            $p = Invoke-StagedSysmonCommand -Exe $exe -Arguments @('-accepteula', '-c', $stage.Path)
          } finally { if ($stage) { $stage.Stream.Dispose(); Remove-Item -LiteralPath $stage.Path -Force -ErrorAction SilentlyContinue } }
          if ($p -and $p.Success -and -not $p.TimedOut -and -not $p.OutputTruncated -and -not $p.StderrTruncated) {
            $actions += "Applied config update"
            $needUpdate = $false
            $lastAppliedHash = $cfgHash
            $summary.LastAppliedSha256 = $lastAppliedHash
          } else {
            $ok = $false
            $warns += ("Update failed: " + ($(if ($p -and $p.TimedOut) { 'timed out' } elseif ($p -and ($p.OutputTruncated -or $p.StderrTruncated)) { 'output was truncated' } elseif ($p) { 'exitcode=' + $p.ExitCode } else { 'native command did not return a result' })))
          }
        } else {
          $ok = $false
          $warns += "Update skipped by ShouldProcess."
        }
      } catch {
        $ok = $false
        $warns += ("Update failed: " + $_.Exception.Message)
      }
    }
    # Re-detect after changes
    $exe = Resolve-SysmonExe -Hint $SysmonExePath
    $svcName = Get-SysmonServiceName
    $eng = Get-SysmonEngineVersion -Exe $exe
    if ($svcName -and $exe -and (-not $previewOnly) -and (-not $explicitExeHint)) { $currentCfgDumpSha = Get-SysmonCurrentConfigSha256 -Exe $exe }
    $summary.SysmonExe = $exe
    $summary.SysmonService = $svcName
    $summary.CurrentDumpSha256 = $currentCfgDumpSha
    if ($eng) { $summary.EngineVersion = $eng.Raw }
  }
  $summary.InstalledNow = $installed
  # Build a redacted source label without leaking internal paths.
  $sourceStr = $null
  if ($ManifestPath) { $sourceStr = 'manifest:[configured path]' }
  elseif ($SourceDir)  { $sourceStr = 'dir:[configured path]' }
  elseif ($ConfigPath) { $sourceStr = 'file:[configured path]' }
  else { $sourceStr = 'file:[configured path]' }
  # Persist state on a best-effort basis.
  $engineRaw = $null
  if ($eng) { $engineRaw = $eng.Raw }
  $newState = @{
    Version = 2
    Time = (Get-Date).ToString('s')
    Host = $env:COMPUTERNAME
    Engine = @{
      Version = $engineRaw
      ExePath = $exe
      Service = $svcName
    }
    Observed = @{
      Path   = $cfgPath
      DesiredSha256 = $cfgHash
      Source = $sourceStr
      Valid  = $valid
    }
    Applied = @{
      Sha256 = $lastAppliedHash
    }
    Runtime = @{
      CurrentDumpSha256 = $currentCfgDumpSha
    }
  }
  $stateWritten = $false
  if (-not $policyBlocked -and $StatePath) {
    $stateWritten = Write-State -p $StatePath -obj $newState
  }
  $summary.StateWritten = [bool]$stateWritten
  if ($stateWritten) {
    $actions += "State updated"
  } else {
    $warns += "State not written (StatePath not set or write failed)."
  }
  # Final drift evaluation
  if ($needUpdate -and (-not $Remediate)) {
    $ok = $false
    $warns += ("Drift detected: desired SHA256=" + $cfgHash + ", last applied=" + ($(if($lastAppliedHash){$lastAppliedHash}else{'n/a'})))
  }
  $summary.DriftDetected = [bool]$needUpdate
  if ($warns.Count -gt 0) { $lines += ("Warnings: " + ($warns -join ' | ')) }
  if ($actions.Count -gt 0) { $lines += ("Actions: " + ($actions -join '; ')) }
  $msg = ($lines -join "`r`n")
  $eventId = 4710
  $level   = 'Warning'
  if ($ok) { $eventId = 4700; $level = 'Information' }
  Write-HealthEvent $eventId $msg $level
  $summary.Ok       = [bool]$ok
  $summary.Actions  = @($actions)
  $summary.Warnings = @($warns)
}
catch {
  $fatalError = $_.Exception.Message
  $ok = $false
  $summary.Ok = $false
  $warns += ("Fatal: " + $fatalError)
  $summary.Warnings = @($warns)
  Write-HealthEvent 4710 ("Sysmon Config Updater: error " + $fatalError) 'Error'
}
finally {
  if (-not $NoConsoleSummary) {
    $pretty = $summary
    if ($SanitizeConsoleOutput) {
      # Sanitize only string fields (keep booleans as-is).
      $pretty = @{}
      foreach ($k in $summary.Keys) {
        $v = $summary[$k]
        if ($v -is [string]) { $pretty[$k] = Sanitize-Text $v }
        elseif ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
          $arr = @()
          foreach ($i in $v) {
            if ($i -is [string]) { $arr += (Sanitize-Text $i) } else { $arr += $i }
          }
          $pretty[$k] = $arr
        } else { $pretty[$k] = $v }
      }
    }
    Write-PrettySummary -Summary $pretty -ChannelSizeMiB $ChannelSizeMiB -Sanitize:$false -NoColor:$NoColor
  }
}
foreach ($w in @($warns)) {
  $code = 'SYSMON-Warning'
  $sev = 'Medium'
  if ($w -match 'allowlist')     { $code = 'SYSMON-AllowlistFail'; $sev = 'High' }
  if ($w -match 'Engine below')  { $code = 'SYSMON-EngineOld'; $sev = 'High' }
  if ($w -match '^Fatal:')       { $code = 'SYSMON-Fatal'; $sev = 'High' }
  if ($w -match 'Manifest validation failed|MinEngine must') { $code = 'SYSMON-PolicyInvalid'; $sev = 'High' }
  if ($w -match 'drift')         { $code = 'SYSMON-Drift'; $sev = 'Medium' }
  if ($w -match 'Install|Update'){ $code = 'SYSMON-ApplyFail'; $sev = 'High' }
  if ($w -match 'Channel not compliant: .*enable failed') { $code = 'Sysmon-ChannelEnableFailed'; $sev = 'Medium' }
  elseif ($w -match 'Channel not compliant: .*resize failed') { $code = 'Sysmon-ChannelResizeFailed'; $sev = 'Medium' }
  elseif ($w -match 'Channel')   { $code = 'SYSMON-Channel'; $sev = 'Low' }
  if ($w -match 'not elevated')  { $code = 'SYSMON-NoAdmin'; $sev = 'Medium' }
  $null = Add-Finding -FindingList $script:Findings -Code $code -Severity $sev -Message $w
}
# V2 output contract
$summary.PolicyBlocked = [bool]$policyBlocked
$resultToken = if ($fatalError -or $policyBlocked -or ($Strict -and ($script:Findings.Count -gt 0 -or -not $ok))) { 'FAIL' } elseif ($script:Findings.Count -gt 0 -or -not $ok) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '16-Sysmon-Config-Updater.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings.ToArray()) -Summary ([pscustomobject]$summary) -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
