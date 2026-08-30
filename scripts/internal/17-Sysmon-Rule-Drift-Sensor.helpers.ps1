#requires -version 5.1
<#
.SYNOPSIS
Internal state, event-query, and remediation helpers for the Sysmon sensor.

.DESCRIPTION
Validates persisted sensor state, performs bounded event queries, classifies
rule drift, and launches remediation through a locked execution closure. The
entry script establishes modules and strict mode before loading these helpers.
#>

function Get-StatusColor {
  param([string]$Status)
  switch ($Status) {
    'OK'                 { 'Green'; break }
    'ANOMALIES_DETECTED' { 'Yellow'; break }
    'CHANNEL_UNAVAILABLE'{ 'Red'; break }
    'ERROR'              { 'Red'; break }
    default              { 'Yellow'; break }
  }
}
function Get-RuleStatusColor {
  param([string]$Status)
  switch ($Status) {
    'OK'         { 'Green'; break }
    'HARDZERO'   { 'Red'; break }
    'LOW'        { 'Yellow'; break }
    'DRIFT_DOWN' { 'Yellow'; break }
    'SURGE'      { 'Yellow'; break }
    default      { 'Yellow'; break }
  }
}
# -----------------------------
# Utility: File IO (safe)
# -----------------------------
function ConvertTo-TrustedStateSidValue {
  param([Parameter(Mandatory)]$IdentityReference)
  try {
    if ($IdentityReference -is [Security.Principal.SecurityIdentifier]) { return $IdentityReference.Value }
    if ($IdentityReference -is [string]) {
      $IdentityReference = New-Object Security.Principal.NTAccount($IdentityReference)
    }
    return $IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
  } catch { throw "State ACL contains an identity that cannot be resolved to a SID: $IdentityReference" }
}
# Rejects sensor state writable by untrusted identities so baseline values
# cannot be manipulated to hide event-rate drift.
function Assert-TrustedStateAcl {
  param([Parameter(Mandatory)][string]$Path)
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return }
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  $trustedSids = @('S-1-5-18','S-1-5-32-544')
  $ownerSid = ConvertTo-TrustedStateSidValue -IdentityReference $acl.Owner
  if ($trustedSids -notcontains $ownerSid) { throw "Sysmon state path '$Path' has an untrusted owner SID '$ownerSid'." }
  if (-not $acl.AreAccessRulesProtected) { throw "Sysmon state path '$Path' must use a protected ACL." }
  $writeMask = [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  foreach ($accessRule in @($acl.Access)) {
    if ($accessRule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    if (($accessRule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
    if (([int64]$accessRule.FileSystemRights -band [int64]$writeMask) -eq 0) { continue }
    $sid = ConvertTo-TrustedStateSidValue -IdentityReference $accessRule.IdentityReference
    if ($trustedSids -notcontains $sid) { throw "Sysmon state path '$Path' grants write access to untrusted SID '$sid'." }
  }
}
function New-TrustedStateAcl {
  param([switch]$Directory)
  $administrators = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544'); $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
  if ($Directory) { $acl = New-Object Security.AccessControl.DirectorySecurity; $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit }
  else { $acl = New-Object Security.AccessControl.FileSecurity; $inheritance = [Security.AccessControl.InheritanceFlags]::None }
  $acl.SetOwner($administrators); $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in @($administrators,$system)) { $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]::FullControl,$inheritance,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow); [void]$acl.AddAccessRule($rule) }
  return $acl
}
function New-TrustedStateDirectory {
  param([Parameter(Mandatory)][string]$Path)
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return [IO.Directory]::CreateDirectory($Path) }
  $security = New-TrustedStateAcl -Directory
  if ($PSVersionTable.PSEdition -eq 'Desktop') { return [IO.Directory]::CreateDirectory($Path,$security) }
  return [IO.FileSystemAclExtensions]::CreateDirectory($security,$Path)
}
function Open-TrustedStateFile {
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][IO.FileMode]$Mode,[Parameter(Mandatory)][IO.FileShare]$Share)
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return [IO.File]::Open($Path,$Mode,[IO.FileAccess]::ReadWrite,$Share) }
  $security = New-TrustedStateAcl
  $rights = [Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write
  $fileInfo = New-Object IO.FileInfo($Path)
  if ($PSVersionTable.PSEdition -eq 'Desktop') { return $fileInfo.Create($Mode,$rights,$Share,4096,[IO.FileOptions]::WriteThrough,$security) }
  return [IO.FileSystemAclExtensions]::Create($fileInfo,$Mode,$rights,$Share,4096,[IO.FileOptions]::WriteThrough,$security)
}
function Get-SysmonStatePath {
  param([string]$RequestedPath,[Parameter(Mandatory)][string]$FileName)
  $root = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'BaselineOpsForWindows\Sysmon'
  $expected = Join-Path $root $FileName
  if ($RequestedPath -and -not [string]::Equals([IO.Path]::GetFullPath($RequestedPath), [IO.Path]::GetFullPath($expected), [StringComparison]::OrdinalIgnoreCase)) { throw 'StatePath is fixed to the admin-owned CommonApplicationData Sysmon state directory.' }
  foreach ($part in @((Split-Path -Parent $root),$root)) {
    if (Test-Path -LiteralPath $part) { $item = Get-Item -LiteralPath $part -Force -ErrorAction Stop; if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Sysmon state path must not contain reparse points.' }; Assert-TrustedStateAcl -Path $item.FullName }
  }
  return $expected
}
function Initialize-SysmonStateDirectory([string]$directory) {
  $commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  if ([string]::IsNullOrWhiteSpace($commonData) -or -not (Test-PathUnderRoot -Path $directory -Root $commonData)) { throw 'Sysmon state directory is outside CommonApplicationData.' }
  $current = [IO.Path]::GetFullPath($commonData)
  $relative = [IO.Path]::GetFullPath($directory).Substring($current.TrimEnd([IO.Path]::DirectorySeparatorChar).Length).TrimStart([IO.Path]::DirectorySeparatorChar)
  foreach ($segment in @($relative -split '[/\\]' | Where-Object { $_ })) { $current = Join-Path $current $segment; if (Test-Path -LiteralPath $current) { $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop; if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Sysmon state directory contains an unsafe path component.' }; Assert-TrustedStateAcl -Path $item.FullName } else { [void](New-TrustedStateDirectory -Path $current) }; Assert-TrustedStateAcl -Path $current }
}
# Enforces a closed, bounded state schema before persisted baseline data is used
# for anomaly calculations.
function Assert-SysmonSensorStateSchema {
  param([Parameter(Mandatory)]$State)
  $fields = @('Version','HostName','Timestamp','WindowHours','Alpha','Baseline','ConfigChanged','CatalogSource')
  if ($State -isnot [pscustomobject] -or @($State.PSObject.Properties.Name).Count -ne $fields.Count -or @($State.PSObject.Properties.Name | Where-Object { $fields -notcontains $_ }).Count -gt 0) { throw 'Sysmon sensor state has missing or unsupported fields.' }
  if (($State.Version -isnot [int] -and $State.Version -isnot [long]) -or [int64]$State.Version -ne 1) { throw 'Sysmon sensor state Version is unsupported.' }
  if ($State.HostName -isnot [string] -or $State.HostName.Length -gt 256 -or $State.Timestamp -isnot [string] -or $State.Timestamp.Length -gt 64 -or $State.CatalogSource -isnot [string] -or $State.CatalogSource.Length -gt 4096) { throw 'Sysmon sensor state contains an invalid bounded string.' }
  if (($State.WindowHours -isnot [int] -and $State.WindowHours -isnot [long]) -or [int64]$State.WindowHours -lt 1 -or [int64]$State.WindowHours -gt 168) { throw 'Sysmon sensor state WindowHours is invalid.' }
  if (($State.Alpha -isnot [double] -and $State.Alpha -isnot [decimal] -and $State.Alpha -isnot [int] -and $State.Alpha -isnot [long]) -or [double]::IsNaN([double]$State.Alpha) -or [double]::IsInfinity([double]$State.Alpha) -or [double]$State.Alpha -lt 0.01 -or [double]$State.Alpha -gt 1.0) { throw 'Sysmon sensor state Alpha is invalid.' }
  if ($State.ConfigChanged -isnot [bool] -or $State.Baseline -isnot [pscustomobject] -or @($State.Baseline.PSObject.Properties).Count -gt 128) { throw 'Sysmon sensor state baseline or ConfigChanged field is invalid.' }
  foreach ($entry in @($State.Baseline.PSObject.Properties)) { if ($entry.Name -notmatch '^[1-9][0-9]{0,4}$' -or [int]$entry.Name -gt 65535 -or ($entry.Value -isnot [double] -and $entry.Value -isnot [decimal] -and $entry.Value -isnot [int] -and $entry.Value -isnot [long]) -or [double]$entry.Value -lt 0 -or [double]$entry.Value -gt 1000000000 -or [double]::IsNaN([double]$entry.Value) -or [double]::IsInfinity([double]$entry.Value)) { throw 'Sysmon sensor state Baseline contains an invalid key or value.' } }
}
# Returns only trusted, schema-valid state; corrupt or untrusted files are
# ignored so the sensor can rebuild a baseline without consuming forged data.
function Read-ValidatedSysmonState {
  param([Parameter(Mandatory)][string]$Path)
  try { if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }; Assert-TrustedStateAcl -Path $Path; $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop; if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Sysmon state is not a regular file.' }; $raw = Get-BoundedUtf8FileContent -Path $item.FullName -MaximumBytes 65536; $state = $raw | ConvertFrom-Json -ErrorAction Stop; Assert-SysmonSensorStateSchema -State $state; return $state } catch { Write-Verbose "Ignoring invalid or untrusted Sysmon sensor state: $($_.Exception.Message)"; return $null }
}
function Write-SysmonState {
  param([Parameter(Mandatory)]$InputObject,[Parameter(Mandatory)][string]$Path)
  Assert-SysmonSensorStateSchema -State $InputObject
  $directory = Split-Path -Parent $Path; Initialize-SysmonStateDirectory -directory $directory
  foreach ($protectedPath in @($Path,$Path + '.lock')) { if (Test-Path -LiteralPath $protectedPath) { $item = Get-Item -LiteralPath $protectedPath -Force -ErrorAction Stop; if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Sysmon state file or lock path is unsafe.' }; Assert-TrustedStateAcl -Path $item.FullName } }
  $lock = Open-TrustedStateFile -Path ($Path + '.lock') -Mode OpenOrCreate -Share ([IO.FileShare]::None); $stage = $null
  try { Assert-TrustedStateAcl -Path ($Path + '.lock'); $stage = Join-Path $directory ('.state-' + [guid]::NewGuid().ToString('N') + '.json'); $json = $InputObject | ConvertTo-Json -Depth 10; $stageStream = Open-TrustedStateFile -Path $stage -Mode CreateNew -Share ([IO.FileShare]::None); try { $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json); $stageStream.Write($bytes,0,$bytes.Length); $stageStream.Flush($true) } finally { $stageStream.Dispose() }; Assert-TrustedStateAcl -Path $stage; if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($stage,$Path,$null) } else { [IO.File]::Move($stage,$Path) }; Assert-TrustedStateAcl -Path $Path } finally { $lock.Dispose(); if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue } }
}
# Read-JsonFile replaced by Read-JsonFileSafe from lib/JsonCatalog.psm1
# Write-JsonFile: replaced by canonical Save-Json from lib/Serialization.psm1
# -----------------------------
# Catalog defaults
# -----------------------------
function Get-DefaultCatalog {
  param(
    [int]$DefaultWindowHours,
    [double]$DefaultAlpha,
    [double]$DefaultRatioFloor,
    [double]$DefaultRatioUpper,
    [int]$DefaultMinBaselineToCompare,
    [switch]$WithBuiltInRules
  )
  $rules = @()
  if ($WithBuiltInRules) {
    $rules = @(
      [pscustomobject]@{ Id = 1;  Name = 'Process Create';  Critical = $true;  MinPerWindow = 1;    MessageRegex = $null; Disabled = $false },
      [pscustomobject]@{ Id = 3;  Name = 'Network Connect'; Critical = $false; MinPerWindow = $null; MessageRegex = $null; Disabled = $false },
      [pscustomobject]@{ Id = 11; Name = 'File Create';     Critical = $false; MinPerWindow = $null; MessageRegex = $null; Disabled = $false },
      [pscustomobject]@{ Id = 16; Name = 'Config Change';   Critical = $false; MinPerWindow = $null; MessageRegex = $null; Disabled = $false },
      [pscustomobject]@{ Id = 22; Name = 'DNS Query';       Critical = $false; MinPerWindow = $null; MessageRegex = $null; Disabled = $false }
    )
  }
  [pscustomobject]@{
    WindowHours = $DefaultWindowHours
    Alpha = $DefaultAlpha
    RatioFloor = $DefaultRatioFloor
    RatioUpper = $DefaultRatioUpper
    MinBaselineToCompare = $DefaultMinBaselineToCompare
    Rules = $rules
  }
}
function Test-CatalogPropertySet {
  param(
    [Parameter(Mandatory)][pscustomobject]$Object,
    [Parameter(Mandatory)][string[]]$Allowed,
    [Parameter(Mandatory)][string]$Context
  )
  $seen = @{}
  foreach ($property in @($Object.PSObject.Properties)) {
    if (-not ($Allowed -contains $property.Name)) { throw "$Context contains unsupported property '$($property.Name)'." }
    $key = $property.Name.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw "$Context contains duplicate property '$($property.Name)'." }
    $seen[$key] = $true
  }
}
function Test-CatalogInteger {
  param([Parameter(Mandatory)]$Value,[Parameter(Mandatory)][string]$Name,[int]$Minimum,[int]$Maximum)
  if ($Value -isnot [long] -and $Value -isnot [int]) { throw "$Name must be an integer." }
  $number = [int64]$Value
  if ($number -lt $Minimum -or $number -gt $Maximum) { throw "$Name must be between $Minimum and $Maximum." }
  return [int]$number
}
function Test-CatalogNumber {
  param([Parameter(Mandatory)]$Value,[Parameter(Mandatory)][string]$Name,[double]$Minimum,[double]$Maximum)
  if ($Value -isnot [long] -and $Value -isnot [int] -and $Value -isnot [double] -and $Value -isnot [decimal]) { throw "$Name must be numeric." }
  $number = [double]$Value
  if ([double]::IsNaN($number) -or [double]::IsInfinity($number) -or $number -lt $Minimum -or $number -gt $Maximum) { throw "$Name must be between $Minimum and $Maximum." }
  return $number
}
function ConvertTo-ValidatedCatalog {
  param([Parameter(Mandatory)]$Catalog)
  if ($Catalog -isnot [pscustomobject]) { throw 'Catalog must be a JSON object.' }
  Test-CatalogPropertySet -Object $Catalog -Allowed @('WindowHours','Alpha','RatioFloor','RatioUpper','MinBaselineToCompare','Rules') -Context 'Catalog'
  if ($Catalog.PSObject.Properties.Name -notcontains 'Rules') { throw 'Catalog must contain Rules.' }
  if ($Catalog.Rules -isnot [System.Array]) { throw 'Catalog.Rules must be an array.' }
  if ($Catalog.Rules.Count -lt 1 -or $Catalog.Rules.Count -gt 128) { throw 'Catalog.Rules must contain between 1 and 128 rules.' }
  foreach ($property in @('WindowHours','Alpha','RatioFloor','RatioUpper','MinBaselineToCompare')) {
    if ($Catalog.PSObject.Properties.Name -contains $property) {
      switch ($property) {
        'WindowHours' { [void](Test-CatalogInteger -Value $Catalog.$property -Name "Catalog.$property" -Minimum 1 -Maximum 168) }
        'MinBaselineToCompare' { [void](Test-CatalogInteger -Value $Catalog.$property -Name "Catalog.$property" -Minimum 0 -Maximum 1000000) }
        'Alpha' { [void](Test-CatalogNumber -Value $Catalog.$property -Name "Catalog.$property" -Minimum 0.01 -Maximum 1.0) }
        'RatioFloor' { [void](Test-CatalogNumber -Value $Catalog.$property -Name "Catalog.$property" -Minimum 0.0 -Maximum 1.0) }
        'RatioUpper' { [void](Test-CatalogNumber -Value $Catalog.$property -Name "Catalog.$property" -Minimum 1.0 -Maximum 1000.0) }
      }
    }
  }
  $seenRuleIds = @{}
  foreach ($rule in @($Catalog.Rules)) {
    if ($rule -isnot [pscustomobject]) { throw 'Each catalog rule must be a JSON object.' }
    Test-CatalogPropertySet -Object $rule -Allowed @('Id','Name','Critical','MinPerWindow','MessageRegex','Disabled') -Context 'Catalog rule'
    if ($rule.PSObject.Properties.Name -notcontains 'Id') { throw 'Each catalog rule must contain Id.' }
    $ruleId = Test-CatalogInteger -Value $rule.Id -Name 'Catalog rule Id' -Minimum 1 -Maximum 65535
    if ($seenRuleIds.ContainsKey($ruleId)) { throw "Catalog contains duplicate rule Id $ruleId." }
    $seenRuleIds[$ruleId] = $true
    if ($rule.PSObject.Properties.Name -contains 'Name' -and ($rule.Name -isnot [string] -or [string]::IsNullOrWhiteSpace($rule.Name) -or $rule.Name.Length -gt 128)) { throw 'Catalog rule Name must be a non-empty string no longer than 128 characters.' }
    foreach ($booleanName in @('Critical','Disabled')) {
      if ($rule.PSObject.Properties.Name -contains $booleanName -and $rule.$booleanName -isnot [bool]) { throw "Catalog rule $booleanName must be boolean." }
    }
    if ($rule.PSObject.Properties.Name -contains 'MinPerWindow' -and $null -ne $rule.MinPerWindow) { [void](Test-CatalogInteger -Value $rule.MinPerWindow -Name 'Catalog rule MinPerWindow' -Minimum 0 -Maximum 1000000) }
    if ($rule.PSObject.Properties.Name -contains 'MessageRegex') {
      if ($null -ne $rule.MessageRegex) {
        if ($rule.MessageRegex -isnot [string] -or $rule.MessageRegex.Length -gt 512) { throw 'Catalog rule MessageRegex must be null or a string no longer than 512 characters.' }
        try { [void][regex]::new($rule.MessageRegex, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant, [TimeSpan]::FromSeconds(1)) } catch { throw "Catalog rule MessageRegex is invalid: $($_.Exception.Message)" }
      }
    }
  }
  return $Catalog
}
function Get-ExplicitCatalog {
  param([Parameter(Mandatory)][string]$Path)
  try {
    $catalogItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($catalogItem.PSIsContainer -or $catalogItem.Length -gt 262144) { throw 'CatalogPath must be a JSON file no larger than 256 KiB.' }
  } catch {
    throw "CatalogPath could not be safely inspected: $($_.Exception.Message)"
  }
  $read = Read-JsonFileWithStatus -Path $Path
  if (-not $read.Meta.Loaded) { throw "CatalogPath $($read.Meta.Status): $($read.Meta.Error)" }
  return (ConvertTo-ValidatedCatalog -Catalog $read.Data)
}
function Write-CatalogFailureResult {
  param([Parameter(Mandatory)][string]$Message)
  $finding = [pscustomobject]@{ Code = 'SYS-CatalogInvalid'; Severity = 'High'; Message = $Message }
  $summary = [pscustomobject]@{ Status = 'ERROR'; CatalogPath = $CatalogPath; Error = $Message }
  $result = Get-V2ResultObject -ScriptName '17-Sysmon-Rule-Drift-Sensor.ps1' -Mode $Mode -Result 'FAIL' -Findings @($finding) -Summary $summary -Metadata @{ CatalogPathProvided = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result 'FAIL')
}
# -----------------------------
# Event Log (audit)
# -----------------------------
function Limit-EventMessage {
  param([Parameter(Mandatory)][string]$Message)
  if ($Message.Length -le $script:MaxEventMessageLength) { return $Message }
  return ($Message.Substring(0, $script:MaxEventMessageLength) + "`r`n[TRUNCATED]")
}
function Write-AuditEvent {
  param(
    [int]$EventId,
    [string]$Message,
    [ValidateSet('Information','Warning','Error')]
    [string]$Level
  )
  $msg = Limit-EventMessage -Message $Message
  if (-not (Write-HealthEvent -LogName $script:EventLogName -Source $script:EventSourceName -Id $EventId -Level $Level -Message $msg)) {
    # Console fallback, do not emit pipeline output.
    Write-UiLine ("[{0}][{1}] {2}" -f $Level,$EventId,$msg)
  }
}
# -----------------------------
# Sysmon channel probe
# -----------------------------
function Get-SysmonChannelStatus {
  $info = [pscustomobject]@{
    LogName = $script:SysmonLogName
    Exists  = $false
    Enabled = $false
    MaxSize = 0
    OldestRecord = $null
    Error = $null
  }
  try {
    # S9 fix: use Invoke-Wevtutil wrapper with array-based args instead of direct wevtutil call
    $wevtResult = Invoke-Wevtutil -Arguments @('gl', $script:SysmonLogName, '/f:xml') -CaptureOutput
    if ($wevtResult -and -not $wevtResult.Success) {
      $info.Error = (@($wevtResult.Output) -join [Environment]::NewLine).Trim()
      return $info
    }
    $xml = if ($wevtResult -and $wevtResult.Output) { (@($wevtResult.Output) -join [Environment]::NewLine) } else { $null }
    if (-not $xml) { return $info }
    $x = [xml]$xml
    $info.Exists = $true
    $enabledText = $null
    try { $enabledText = $x.channel.enabled.'#text' } catch { $enabledText = $null }
    if ($null -ne $enabledText -and $enabledText -ne '') {
      $info.Enabled = [bool]::Parse([string]$enabledText)
    }
    $maxText = $null
    try { $maxText = $x.channel.logging.maxSize.'#text' } catch { $maxText = $null }
    if ($maxText) { $info.MaxSize = [int64]$maxText }
  } catch {
    $info.Error = $_.Exception.Message
  }
  return $info
}
function Enable-SysmonChannelIfRequested {
  param([pscustomobject]$ChannelStatus)
  if ($Mode -ne 'Remediate' -or -not $AttemptEnableChannel) { return $ChannelStatus }
  if (-not $ChannelStatus.Exists) { return $ChannelStatus }
  if ($ChannelStatus.Enabled) { return $ChannelStatus }
  if (-not (Test-IsAdmin)) { return $ChannelStatus }
  try {
    # S9 fix: use Invoke-Wevtutil wrapper with array-based args instead of direct wevtutil call
    Invoke-Wevtutil -Arguments @('sl', $script:SysmonLogName, '/e:true') | Out-Null
  } catch {
    Write-Verbose ("Sysmon channel enable failed: {0}" -f $_.Exception.Message)
  }
  return (Get-SysmonChannelStatus)
}
# -----------------------------
# Counting
# -----------------------------
# Runs Get-WinEvent in a disposable pipeline with count and time limits because
# a busy or damaged event channel must not block the monitoring run indefinitely.
function Invoke-BoundedSysmonEventQuery {
  param(
    [Parameter(Mandatory)][hashtable]$FilterHashtable,
    [Parameter(Mandatory)][int]$MaximumEvents,
    [Parameter(Mandatory)][int]$MaximumSeconds
  )
  $pipeline = [powershell]::Create()
  $async = $null
  $events = @(); $queryError = $null; $timedOut = $false
  $stopwatch = [Diagnostics.Stopwatch]::StartNew()
  try {
    [void]$pipeline.AddCommand('Get-WinEvent').AddParameter('FilterHashtable',$FilterHashtable).AddParameter('MaxEvents',($MaximumEvents + 1)).AddParameter('ErrorAction','Stop')
    $async = $pipeline.BeginInvoke()
    if (-not $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($MaximumSeconds))) {
      $timedOut = $true
      try { $pipeline.Stop() } catch { Write-Verbose "Stopping timed-out Sysmon event query failed: $($_.Exception.Message)" }
    } else {
      $invokeException = $null
      try { $events = @($pipeline.EndInvoke($async)) } catch { $invokeException = $_.Exception.Message }
      $queryErrors = @($pipeline.Streams.Error)
      $materialErrors = @($queryErrors | Where-Object { $_.FullyQualifiedErrorId -notmatch '^NoMatchingEventsFound(?:,|$)' })
      if ($materialErrors.Count -gt 0) { $queryError = ($materialErrors | ForEach-Object { $_.Exception.Message } | Select-Object -Unique) -join '; ' }
      elseif ($invokeException -and $queryErrors.Count -eq 0) { $queryError = $invokeException }
    }
  } catch { $queryError = $_.Exception.Message }
  finally {
    $stopwatch.Stop()
    if ($async -and $async.AsyncWaitHandle) { $async.AsyncWaitHandle.Close() }
    $pipeline.Dispose()
  }
  [pscustomobject]@{ Events = $events; Error = $queryError; TimedOut = $timedOut; ElapsedMilliseconds = $stopwatch.ElapsedMilliseconds }
}
function Get-BoundedSysmonEventEvidence {
  param(
    [Parameter(Mandatory)][int[]]$EventIds,
    [Parameter(Mandatory)][datetime]$StartTime,
    [Parameter(Mandatory)][int]$MaximumEvents,
    [Parameter(Mandatory)][int]$MaximumSeconds
  )
  $uniqueIds = @($EventIds | Sort-Object -Unique)
  $stopwatch = [Diagnostics.Stopwatch]::StartNew()
  $events = New-Object System.Collections.Generic.List[object]
  $truncated = $false; $timedOut = $false; $queryError = $null
  try {
    $filter = @{ LogName = $script:SysmonLogName; ID = $uniqueIds; StartTime = $StartTime }
    $query = Invoke-BoundedSysmonEventQuery -FilterHashtable $filter -MaximumEvents $MaximumEvents -MaximumSeconds $MaximumSeconds
    $queryError = $query.Error; $timedOut = [bool]$query.TimedOut
    foreach ($eventRecord in @($query.Events)) {
      if ($stopwatch.Elapsed.TotalSeconds -ge $MaximumSeconds) { $timedOut = $true; break }
      if ($events.Count -ge $MaximumEvents) { $truncated = $true; break }
      [void]$events.Add($eventRecord)
    }
  } catch { $queryError = $_.Exception.Message }
  finally { if ($stopwatch.Elapsed.TotalSeconds -ge $MaximumSeconds) { $timedOut = $true }; $stopwatch.Stop() }
  [pscustomobject]@{
    Complete = [bool](-not $queryError -and -not $truncated -and -not $timedOut)
    Truncated = $truncated
    TimedOut = $timedOut
    Error = $(if ($queryError) { $queryError } elseif ($timedOut) { 'Event query or processing exceeded its global wall-clock budget.' } elseif ($truncated) { 'Event evidence exceeded the global event-count budget.' } else { $null })
    EventIds = $uniqueIds
    EventsRead = $events.Count
    MaximumEvents = $MaximumEvents
    MaximumSeconds = $MaximumSeconds
    ElapsedMilliseconds = $stopwatch.ElapsedMilliseconds
    Events = @($events.ToArray())
  }
}
function Get-EventCountFromEvidence {
  param([Parameter(Mandatory)]$Evidence,[Parameter(Mandatory)][int]$EventId,[string]$MessageRegex,[Parameter(Mandatory)][Diagnostics.Stopwatch]$WorkStopwatch,[Parameter(Mandatory)][int]$MaximumSeconds)
  if (-not $Evidence.Complete) { return [pscustomobject]@{ Success = $false; Count = $null; Error = $(if ($Evidence.Error) { $Evidence.Error } else { 'Event evidence is incomplete or truncated.' }) } }
  try {
    $rx = if ([string]::IsNullOrWhiteSpace($MessageRegex)) { $null } else { [regex]::new($MessageRegex,[Text.RegularExpressions.RegexOptions]::CultureInvariant,[TimeSpan]::FromSeconds(1)) }
    $count = 0
    foreach ($eventRecord in @($Evidence.Events)) {
      if ($WorkStopwatch.Elapsed.TotalSeconds -ge $MaximumSeconds) { return [pscustomobject]@{ Success = $false; Count = $null; Error = 'Event processing exceeded its global wall-clock budget.' } }
      if ([int]$eventRecord.Id -eq $EventId -and ($null -eq $rx -or $rx.IsMatch([string]$eventRecord.Message))) { $count++ }
    }
    return [pscustomobject]@{ Success = $true; Count = $count; Error = $null }
  } catch { return [pscustomobject]@{ Success = $false; Count = $null; Error = $_.Exception.Message } }
}
function Resolve-SysmonOverallStatus {
  param([object[]]$Rules,[bool]$StateWriteOk,[bool]$EvidenceComplete)
  if (-not $EvidenceComplete -or @($Rules | Where-Object { $_.Status -in @('QUERY_ERROR','INCOMPLETE') }).Count -gt 0) { return 'ERROR' }
  if (@($Rules | Where-Object { $_.Status -ne 'OK' }).Count -gt 0 -or -not $StateWriteOk) { return 'ANOMALIES_DETECTED' }
  return 'OK'
}
# -----------------------------
# Remediation
# -----------------------------
# HARDZERO remediation launches another PowerShell script, so normalize the path
# to a real file inside this repo's scripts directory before any signature check
# or process launch. This prevents catalog/profile input from selecting an
# arbitrary local script through traversal or reparse points.
function Resolve-RemediationScriptPath {
  param([Parameter(Mandatory)][string]$ScriptPath)
  $scriptRoot = Split-Path -Parent $PSScriptRoot  # repo root
  $scriptsDir = Join-Path $scriptRoot 'scripts'
  try {
    $resolvedScriptsDir = Resolve-Path -LiteralPath $scriptsDir -ErrorAction Stop
    $resolvedScriptPath = Resolve-Path -LiteralPath $ScriptPath -ErrorAction Stop
  } catch {
    throw "Resolve-RemediationScriptPath: ScriptPath '$ScriptPath' is missing or cannot be resolved."
  }
  $canonicalScriptsDir = $resolvedScriptsDir.ProviderPath
  $canonicalScriptPath = $resolvedScriptPath.ProviderPath
  if (-not (Test-PathUnderRoot -Path $canonicalScriptPath -Root $canonicalScriptsDir)) {
    throw "Resolve-RemediationScriptPath: ScriptPath '$ScriptPath' is not under the expected scripts directory."
  }
  if (Test-PathContainsReparsePoint -Path $resolvedScriptPath.Path -Root $resolvedScriptsDir.Path) {
    throw "Resolve-RemediationScriptPath: ScriptPath '$ScriptPath' traverses a reparse point."
  }
  $scriptFileName = Split-Path -Leaf $canonicalScriptPath
  if (-not (Test-SafeScriptName -Name $scriptFileName)) {
    throw "Resolve-RemediationScriptPath: ScriptPath file name '$scriptFileName' failed safety validation."
  }
  try {
    $scriptItem = Get-Item -LiteralPath $canonicalScriptPath -Force -ErrorAction Stop
  } catch {
    throw "Resolve-RemediationScriptPath: ScriptPath '$ScriptPath' is missing or cannot be inspected."
  }
  if ($scriptItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw "Resolve-RemediationScriptPath: ScriptPath '$ScriptPath' is a reparse point."
  }
  return $canonicalScriptPath
}
# Enumerates the fixed code closure required by remediation; explicit membership
# prevents arbitrary files added to lib/ or scripts/ from becoming executable.
function Get-SysmonRemediationExecutionClosure {
  param([Parameter(Mandatory)][string]$ScriptPath)
  # The updater resolves only these files before it starts privileged work. Keep
  # this list explicit: discovering arbitrary files from lib would make the
  # trusted execution boundary depend on directory contents.
  $scriptsDirectory = Split-Path -Parent $ScriptPath
  $repositoryRoot = Split-Path -Parent $scriptsDirectory
  $expectedEntryScript = Join-Path $scriptsDirectory '16-Sysmon-Config-Updater.ps1'
  if (-not [string]::Equals([IO.Path]::GetFullPath($ScriptPath), [IO.Path]::GetFullPath($expectedEntryScript), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Remediation execution is restricted to 16-Sysmon-Config-Updater.ps1.'
  }

  $closurePaths = @(
    $expectedEntryScript,
    (Join-Path $scriptsDirectory 'internal\16-Sysmon-Config-Updater.helpers.ps1'),
    (Join-Path $scriptsDirectory '_lib\Bootstrap.ps1')
  )
  foreach ($moduleName in @('Output.psm1','Common.psm1','EventLog.psm1','Evidence.psm1','External.psm1','Results.psm1','Serialization.psm1','Validation.psm1')) {
    $closurePaths += Join-Path $repositoryRoot (Join-Path 'lib' $moduleName)
  }
  # External.psm1 dot-sources these platform implementations. Lock them with
  # the facade so a privileged launch cannot observe an unlocked code path.
  foreach ($platformFile in @('Executable.ps1','NativeProcess.ps1','NativeTools.ps1','WindowsOperations.ps1')) {
    $closurePaths += Join-Path $repositoryRoot (Join-Path 'lib\platform' $platformFile)
  }
  return @($closurePaths)
}

# Verifies every closure member is a trusted regular file before the caller
# acquires handles that keep those exact files immutable during launch.
function Assert-LockedSysmonRemediationClosure {
  param(
    [Parameter(Mandatory)][string[]]$ClosurePaths,
    [Parameter(Mandatory)][string]$RepositoryRoot
  )
  foreach ($closurePath in $ClosurePaths) {
    $item = Get-Item -LiteralPath $closurePath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Test-PathContainsReparsePoint -Path $item.FullName -Root $RepositoryRoot)) {
      throw 'Remediation execution closure contains a reparse point or non-file item.'
    }
    Assert-TrustedWindowsPathAcl -Path $item.FullName -CheckAncestors | Out-Null
  }
}
# Launches only the trusted updater closure in Windows PowerShell and reports a
# structured outcome; the sensor never remediates inline in its own process.
function Invoke-RemediationScript {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory)][string]$ScriptPath,
    [switch]$RequireSignature
  )
  $ScriptPath = Resolve-RemediationScriptPath -ScriptPath $ScriptPath
  $stage = $null
  $result = [pscustomobject]@{
    Attempted = $true
    Success = $false
    ExitCode = $null
    Error = $null
    ScriptPath = $ScriptPath
  }
  try {
    $windowsPowerShell = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'WindowsPowerShell\v1.0\powershell.exe'
    if (-not [System.IO.Path]::IsPathRooted($windowsPowerShell) -or -not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) { throw 'The absolute Windows PowerShell executable could not be found.' }
    $windowsPowerShell = (Assert-TrustedWindowsPathAcl -Path $windowsPowerShell -CheckAncestors).FullName
    if (-not $PSCmdlet.ShouldProcess($ScriptPath, 'Launch trusted remediation PowerShell process')) {
      $result.Attempted = $false
      return $result
    }
    # Do not stage a lone entry script: it changes PSScriptRoot and breaks its
    # trusted imports. Instead, lock the explicit original execution closure
    # before evaluating ACLs or the entry script signature, and keep every
    # deny-write/delete handle open until the child process exits.
    $scriptsDirectory = Split-Path -Parent $ScriptPath
    $repositoryRoot = Split-Path -Parent $scriptsDirectory
    $closurePaths = Get-SysmonRemediationExecutionClosure -ScriptPath $ScriptPath
    $stage = [pscustomobject]@{ Path = $ScriptPath; Streams = @() }
    foreach ($closurePath in $closurePaths) {
      $item = Get-Item -LiteralPath $closurePath -Force -ErrorAction Stop
      $stage.Streams += [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    }
    Assert-LockedSysmonRemediationClosure -ClosurePaths $closurePaths -RepositoryRoot $repositoryRoot
    if ($RequireSignature) {
      $signature = Get-AuthenticodeSignature -FilePath $ScriptPath -ErrorAction Stop
      if ($signature.Status -ne 'Valid') { throw "Remediation script signature is not valid: $($signature.Status)." }
    }
    $argList = @('-NoProfile')
    if ($AllowExecutionPolicyBypass) { $argList += @('-ExecutionPolicy', 'Bypass') }
    $argList += @('-File', $stage.Path, '-Mode', 'Remediate')
    $native = Invoke-NativeCommand -Command $windowsPowerShell -Arguments $argList -CaptureOutput -Quiet -TimeoutSeconds 300 -MaxOutputBytes 65536
    $result.ExitCode = if ($native) { $native.ExitCode } else { $null }
    $result.Success = [bool]($native -and $native.Success -and -not $native.TimedOut -and -not $native.OutputTruncated -and -not $native.StderrTruncated)
    if (-not $result.Success -and $native) { $result.Error = (($native.Stderr, $native.Stdout | Where-Object { $_ }) -join [Environment]::NewLine).Trim() }
  } catch {
    $result.Error = $_.Exception.Message
  } finally {
    if ($stage) {
      foreach ($stream in @($stage.Streams)) { $stream.Dispose() }
    }
  }
  return $result
}
# -----------------------------
# Result objects (pipeline)
# -----------------------------
function Get-RuleResult {
  param(
    [int]$Id,
    [string]$Name,
    [Nullable[int]]$Count,
    [Nullable[double]]$PriorBaseline,
    [Nullable[double]]$NewBaseline,
    [Nullable[double]]$Ratio,
    [Nullable[int]]$MinPerWindow,
    [bool]$IsCritical,
    [string]$Status,
    [string]$MessageRegex,
    [string]$QueryError
  )
  [pscustomobject]@{
    Id = $Id
    Name = $Name
    Count = $Count
    PriorBaseline = $PriorBaseline
    Baseline = $NewBaseline
    Ratio = $Ratio
    MinPerWindow = $MinPerWindow
    IsCritical = $IsCritical
    Status = $Status
    MessageRegex = $MessageRegex
    QueryError = $QueryError
  }
}
function Get-FinalResult {
  param(
    [string]$OverallStatus,
    [datetime]$StartTime,
    [pscustomobject]$ChannelStatus,
    [Nullable[bool]]$ConfigChanged,
    [pscustomobject]$Remediation,
    [object[]]$Rules,
    [AllowNull()]$Evidence,
    [string]$CatalogSource,
    [string]$StatePathUsed,
    [bool]$StateWriteOk
  )
  $anoms = ($Rules | Where-Object { $_.Status -ne 'OK' } | Measure-Object).Count
  $hardZeros = ($Rules | Where-Object { $_.Status -eq 'HARDZERO' } | Measure-Object).Count
  [pscustomobject]@{
    Timestamp = (Get-Date).ToString('s')
    HostName = $env:COMPUTERNAME
    WindowHours = $WindowHours
    StartTime = $StartTime.ToString('s')
    Status = $OverallStatus
    CatalogSource = $CatalogSource
    StatePath = $StatePathUsed
    StateWriteOk = $StateWriteOk
    ConfigChanged = $ConfigChanged
    Evidence = $Evidence
    Channel = $ChannelStatus
    Remediation = $Remediation
    Summary = [pscustomobject]@{
      TotalRules = $Rules.Count
      Anomalies = $anoms
      HardZero = $hardZeros
    }
    Rules = $Rules
  }
}
# -----------------------------
# Console summary (no pipeline pollution)
# -----------------------------
function Show-ConsoleSummary {
  param([Parameter(Mandatory)][pscustomobject]$Result)
  $statusColor = Get-StatusColor -Status $Result.Status
  Write-UiSeparator -Char '=' -Width 78 -Style 'Cyan'
  Write-ConsoleLine -Text ("Sysmon Drift Sensor  |  Host: {0}  |  Time: {1}" -f $Result.HostName, $Result.Timestamp) -Color 'Cyan'
  Write-UiSeparator -Char '=' -Width 78 -Style 'Cyan'
  Write-ConsoleLine -Text ("Status: {0}" -f $Result.Status) -Color $statusColor
  Write-ConsoleLine -Text ("WindowHours: {0} | Rules: {1} | Anomalies: {2} | HardZero: {3}" -f $Result.WindowHours, $Result.Summary.TotalRules, $Result.Summary.Anomalies, $Result.Summary.HardZero) -Color 'White'
  $oldestTxt = 'n/a'
  if ($Result.Channel.OldestRecord) { $oldestTxt = $Result.Channel.OldestRecord.ToString('s') }
  Write-ConsoleLine -Text ("Channel: Exists={0} Enabled={1} Oldest={2}" -f $Result.Channel.Exists, $Result.Channel.Enabled, $oldestTxt) -Color 'White'
  if ($Result.Channel.Error) {
    Write-ConsoleLine -Text ("ChannelError: {0}" -f $Result.Channel.Error) -Color 'Yellow'
  }
  Write-ConsoleLine -Text ("ConfigChangedInWindow: {0}" -f $Result.ConfigChanged) -Color 'White'
  Write-ConsoleLine -Text ("Catalog: {0}" -f $Result.CatalogSource) -Color 'White'
  Write-ConsoleLine -Text ("State: {0} | WriteOk: {1}" -f $Result.StatePath, $Result.StateWriteOk) -Color 'White'
  if ($Result.Remediation -and $Result.Remediation.Attempted) {
    $rc = 'Yellow'
    if ($Result.Remediation.Success) { $rc = 'Green' }
    if (-not $Result.Remediation.Success) { $rc = 'Red' }
    Write-ConsoleLine -Text ("Remediation: Success={0} ExitCode={1}" -f $Result.Remediation.Success, $Result.Remediation.ExitCode) -Color $rc
    if ($Result.Remediation.Error) {
      Write-ConsoleLine -Text ("RemediationError: {0}" -f $Result.Remediation.Error) -Color 'Yellow'
    }
  }
  # Print top anomalies for console review.
  if ($Result.Rules -and $Result.Rules.Count -gt 0) {
    $bad = @($Result.Rules | Where-Object { $_.Status -ne 'OK' } | Sort-Object Status, Id)
    if ($bad.Count -gt 0) {
      Write-UiLine ""
      Write-ConsoleLine -Text "Top anomalies:" -Color 'Cyan'
      $bad | Select-Object -First 20 | ForEach-Object {
        $c = Get-RuleStatusColor -Status $_.Status
        $baseTxt = 'n/a'
        if ($null -ne $_.PriorBaseline) { $baseTxt = ([math]::Round([double]$_.PriorBaseline, 1)).ToString() }
        $ratioTxt = 'n/a'
        if ($null -ne $_.Ratio) { $ratioTxt = $_.Ratio.ToString() }
        Write-ConsoleLine -Text ("  ID {0,-4} | {1,-26} | Cnt {2,-6} | Base {3,-8} | Ratio {4,-6} | {5}" -f $_.Id, $_.Name, $_.Count, $baseTxt, $ratioTxt, $_.Status) -Color $c
      }
      if ($bad.Count -gt 20) {
        Write-ConsoleLine -Text ("  ... and {0} more" -f ($bad.Count - 20)) -Color 'Gray'
      }
    }
  }
  # Next steps hints (only for humans)
  if ($Result.Status -eq 'CHANNEL_UNAVAILABLE') {
    Write-UiLine ""
    Write-ConsoleLine -Text "Next steps:" -Color 'Cyan'
    Write-ConsoleLine -Text "  - Check if Sysmon is installed and running (Sysmon/Sysmon64 service)." -Color 'Gray'
    Write-ConsoleLine -Text "  - List logs: wevtutil el | findstr /i sysmon" -Color 'Gray'
    Write-ConsoleLine -Text "  - If log exists but disabled: run as admin and enable it: wevtutil sl Microsoft-Windows-Sysmon/Operational /e:true" -Color 'Gray'
  }
  Write-UiSeparator -Char '=' -Width 78 -Style 'Cyan'
  Write-UiLine ""
}
