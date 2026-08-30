<#
.SYNOPSIS
  Invokes an approved fixed native tool through the native command boundary.
.DESCRIPTION
  Restricts callers to the Windows tools exposed by the public compatibility
  wrappers while keeping their native invocation semantics consistent.
#>
function Invoke-FixedNativeTool {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateSet('schtasks.exe', 'auditpol.exe', 'wevtutil.exe', 'wecutil.exe', 'reg.exe')]
    [string]$Tool,

    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput,
    [ValidateRange(1, 86400)][int]$TimeoutSeconds = 300,
    [ValidateRange(1024, 10485760)][int]$MaxOutputBytes = 1048576
  )

  return (Invoke-NativeCommand -Command $Tool -Arguments $Arguments `
      -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput -TimeoutSeconds $TimeoutSeconds -MaxOutputBytes $MaxOutputBytes)
}

<#
.SYNOPSIS
  Wrapper for schtasks.exe with exit code validation.
#>
function Invoke-Schtasks {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput
  )

  return (Invoke-FixedNativeTool -Tool 'schtasks.exe' -Arguments $Arguments -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput)
}

<#
.SYNOPSIS
  Wrapper for auditpol.exe with exit code validation.
#>
function Invoke-Auditpol {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput
  )

  return (Invoke-FixedNativeTool -Tool 'auditpol.exe' -Arguments $Arguments -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput)
}

<#
.SYNOPSIS
  Wrapper for wevtutil.exe with exit code validation.
#>
function Invoke-Wevtutil {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput
  )

  return (Invoke-FixedNativeTool -Tool 'wevtutil.exe' -Arguments $Arguments -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput)
}

<#
.SYNOPSIS
  Wrapper for wecutil.exe with exit code validation.
#>
function Invoke-Wecutil {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput
  )

  return (Invoke-FixedNativeTool -Tool 'wecutil.exe' -Arguments $Arguments -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput)
}

<#
.SYNOPSIS
  Wrapper for reg.exe with exit code validation.
#>
function Invoke-RegExe {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput
  )

  return (Invoke-FixedNativeTool -Tool 'reg.exe' -Arguments $Arguments -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput)
}

<#
.SYNOPSIS
  Invokes the trusted System32 WinRM script through the trusted cscript host.
#>
function Invoke-WinrmCommand {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string[]]$Arguments,
    [switch]$ThrowOnError,
    [switch]$CaptureOutput,
    [switch]$Quiet,
    [ValidateRange(1, 86400)][int]$TimeoutSeconds = 300,
    [ValidateRange(1024, 10485760)][int]$MaxOutputBytes = 1048576
  )

  $winrmScript = Resolve-TrustedWindowsSystemFile -LeafName 'winrm.vbs'
  if ([string]::IsNullOrWhiteSpace($winrmScript)) {
    $message = 'Trusted WinRM script not found.'
    if ($ThrowOnError) { throw $message }
    if (-not $Quiet) { Write-Warning $message }
    return $null
  }

  $scriptLock = $null
  try {
    $scriptLock = [IO.File]::Open($winrmScript, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    return Invoke-NativeCommand -Command 'cscript.exe' -Arguments (@('//NoLogo', $winrmScript) + $Arguments) `
      -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput -Quiet:$Quiet `
      -TimeoutSeconds $TimeoutSeconds -MaxOutputBytes $MaxOutputBytes
  } finally {
    if ($null -ne $scriptLock) { $scriptLock.Dispose() }
  }
}

<#
.SYNOPSIS
  Wrapper for git with optional working directory and exit code validation.
.PARAMETER Arguments
  Arguments to pass to git.
.PARAMETER WorkingDirectory
  Directory to run git in.
.PARAMETER ThrowOnError
  Throw on non-zero exit code.
.PARAMETER CaptureOutput
  Return structured output object.
#>
function Invoke-Git {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [string]$WorkingDirectory,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput
  )

  $gitPath = Resolve-TrustedGitPath
  if ([string]::IsNullOrWhiteSpace($gitPath)) {
    $msg = "git command not found. Please install Git."
    if ($ThrowOnError) {
      throw $msg
    }
    Write-Warning $msg
    return $null
  }

  # Use git -C instead of Set-Location to avoid changing process working directory
  $gitArgs = if ($WorkingDirectory) {
    @('-C', $WorkingDirectory) + $Arguments
  } else {
    $Arguments
  }

  $result = Invoke-NativeCommand -Command $gitPath -Arguments $gitArgs `
    -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput
  return $result
}
