<#
.SYNOPSIS
  Retrieves all audit policy subcategories via auditpol.exe.
.DESCRIPTION
  Implements focused Windows event-log, scheduled-task, and registry
  operations behind the External module.
#>
function Get-AuditPolSubcategories {
  [CmdletBinding()]
  param()

  $result = Invoke-Auditpol -Arguments @('/get', '/category:*') -CaptureOutput

  if ($result -and $result.Success -and -not $result.TimedOut -and -not $result.OutputTruncated -and -not $result.StderrTruncated) {
    return $result.Output
  }

  return $null
}

<#
.SYNOPSIS
  Gets event log configuration via wevtutil.exe.
.PARAMETER LogName
  Name of the event log to query.
#>
function Get-EventLogInfo {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$LogName
  )

  $result = Invoke-Wevtutil -Arguments @('gl', $LogName) -CaptureOutput

  if ($result -and $result.Success -and -not $result.TimedOut -and -not $result.OutputTruncated -and -not $result.StderrTruncated) {
    return $result.Output
  }

  return $null
}

<#
.SYNOPSIS
  Enables a Windows event log via wevtutil.exe.
.PARAMETER LogName
  Name of the event log to enable.
#>
function Enable-EventLog {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$LogName
  )

  $result = Invoke-Wevtutil -Arguments @('sl', $LogName, '/e:true')
  return ($result -eq $true)
}

<#
.SYNOPSIS
  Sets the maximum size of a Windows event log via wevtutil.exe.
.PARAMETER LogName
  Name of the event log.
.PARAMETER MaxSizeBytes
  Maximum log size in bytes.
#>
function Set-EventLogMaxSize {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)]
    [string]$LogName,

    [Parameter(Mandatory)]
    [int64]$MaxSizeBytes
  )

  if (-not $PSCmdlet.ShouldProcess($LogName, "Set event log max size to $MaxSizeBytes bytes")) {
    return $false
  }
  $result = Invoke-Wevtutil -Arguments @('sl', $LogName, "/ms:$MaxSizeBytes")
  return ($result -eq $true)
}

<#
.SYNOPSIS
  Exports an event log to a file via wevtutil.exe.
.PARAMETER LogName
  Name of the event log to export.
.PARAMETER OutputPath
  File path for the exported .evtx file.
.PARAMETER Query
  Optional XPath query to filter events.
#>
function Export-EventLog {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$LogName,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [string]$Query
  )

  # Validate XPath query contains only safe characters to prevent injection
  if ($Query -and $Query -notmatch '^[a-zA-Z0-9\s\[\]/\x27"=*@\.\-_(),]+$') {
    throw "Export-EventLog: Query contains unsafe characters. Only letters, digits, spaces, brackets, slashes, quotes, equals, stars, at-signs, dots, hyphens, underscores, parentheses, and commas are allowed."
  }

  $wevtArgs = @('epl', $LogName, $OutputPath, '/ow:true')
  if ($Query) {
    $wevtArgs += "/q:$Query"
  }

  $result = Invoke-Wevtutil -Arguments $wevtArgs -ThrowOnError
  return ($result -eq $true)
}

<#
.SYNOPSIS
  Creates a scheduled task via schtasks.exe.
.PARAMETER TaskName
  Name (and optional folder path) for the task.
.PARAMETER TaskRun
  Command or script the task will execute.
.PARAMETER Schedule
  Trigger schedule type (default: ONCE).
.PARAMETER StartTime
  Start time for the trigger.
.PARAMETER RunLevel
  Run level (default: HIGHEST).
.PARAMETER Force
  Overwrite an existing task with the same name.
#>
function New-MdmScheduledTask {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$TaskName,

    [Parameter(Mandatory)]
    [string]$TaskRun,

    [string]$Schedule = 'ONCE',

    [string]$StartTime,

    [string]$RunLevel = 'HIGHEST',

    [switch]$Force
  )

  # S16 fix: validate TaskName to prevent path traversal in task folders and special chars.
  # Callers are responsible for validating $TaskRun content beyond these basic guards.
  if ($TaskRun -match '^-') {
    throw "New-MdmScheduledTask: TaskRun must not start with '-' (option injection prevention)."
  }
  if ($TaskRun -match '\.\.') {
    throw "New-MdmScheduledTask: TaskRun must not contain '..' (path traversal prevention)."
  }
  if ($TaskName -notmatch '^[a-zA-Z0-9\-_\\]+$') {
    throw "New-MdmScheduledTask: TaskName contains invalid characters. Only alphanumeric, hyphens, underscores, and backslashes (for task folders) are allowed."
  }

  $taskArgs = @('/Create', '/TN', $TaskName, '/SC', $Schedule, '/TR', $TaskRun, '/RL', $RunLevel)
  if ($Force) { $taskArgs += '/F' }
  if ($StartTime) { $taskArgs += '/ST', $StartTime }

  if (-not $PSCmdlet.ShouldProcess($TaskName, 'Create scheduled task')) {
    return $false
  }
  $result = Invoke-Schtasks -Arguments $taskArgs -ThrowOnError
  return ($result -eq $true)
}

<#
.SYNOPSIS
  Removes a scheduled task via schtasks.exe.
.PARAMETER TaskName
  Name of the task to remove.
#>
function Remove-ScheduledTask {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)]
    [string]$TaskName
  )

  if (-not $PSCmdlet.ShouldProcess($TaskName, 'Remove scheduled task')) {
    return $false
  }
  $result = Invoke-Schtasks -Arguments @('/Delete', '/TN', $TaskName, '/F')
  return ($result -eq $true)
}

<#
.SYNOPSIS
  Exports a registry key to a .reg file via reg.exe.
.PARAMETER KeyPath
  Registry key path to export.
.PARAMETER OutputPath
  File path for the exported .reg file.
#>
function Export-RegistryKey {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$KeyPath,

    [Parameter(Mandatory)]
    [string]$OutputPath
  )

  if (Test-PathTraversal -Path $OutputPath) {
    throw "Path traversal not allowed in OutputPath"
  }
  if ($KeyPath -match '\\(SAM|SECURITY)\\') {
    throw "Export of sensitive registry hives is blocked"
  }

  $result = Invoke-RegExe -Arguments @('export', $KeyPath, $OutputPath, '/y') -ThrowOnError
  return ($result -eq $true)
}
