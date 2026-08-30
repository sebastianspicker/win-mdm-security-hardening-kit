<#
.SYNOPSIS
  Tests whether an external command exists in PATH.
.DESCRIPTION
  Implements executable discovery and trust checks for the External module.
.PARAMETER Name
  Executable name to look up.
#>
function Test-CommandExists {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Name
  )

  return -not [string]::IsNullOrWhiteSpace((Resolve-NativeExecutablePath -Name $Name))
}

<#
.SYNOPSIS
  Resolves a trusted absolute path for a native executable.
.DESCRIPTION
  Rejects non-file, non-rooted, and reparse-point paths before invocation.
#>
function Resolve-NativeExecutablePath {
  [CmdletBinding()]
  [OutputType([string])]
  param([Parameter(Mandatory)][string]$Name)

  if ([string]::IsNullOrWhiteSpace($Name) -or $Name -match '[\x00-\x1F\x7F]') { return $null }

  $windowsHost = $script:IsWindowsHost
  $leafName = [System.IO.Path]::GetFileName($Name)
  $hasPathComponent = $leafName -ne $Name
  $systemExecutables = @(
    'auditpol.exe','bcdedit.exe','certutil.exe','cscript.exe','dism.exe','manage-bde.exe',
    'netstat.exe','reg.exe','sc.exe','schtasks.exe','taskkill.exe','vssadmin.exe',
    'wecutil.exe','wevtutil.exe','w32tm.exe'
  )

  if ($windowsHost -and -not $hasPathComponent) {
    if ($systemExecutables -icontains $Name) { return (Resolve-TrustedWindowsSystemFile -LeafName $Name) }
    if ($Name -ieq 'winget.exe' -or $Name -ieq 'winget') { return (Resolve-TrustedWingetPath) }
    if ($Name -ieq 'git.exe' -or $Name -ieq 'git') { return (Resolve-TrustedGitPath) }

    # The current PowerShell host is already executing and therefore has a
    # stable identity; permit only that exact host for bare-name self-spawns.
    $hostPath = try { (Get-Process -Id $PID -ErrorAction Stop).Path } catch { $null }
    $requestedHostLeaf = if ([IO.Path]::HasExtension($Name)) { $Name } else { "$Name.exe" }
    if (-not [string]::IsNullOrWhiteSpace($hostPath) -and [IO.Path]::GetFileName($hostPath) -ieq $requestedHostLeaf) {
      return [IO.Path]::GetFullPath($hostPath)
    }
    return $null
  }

  try {
    if ($hasPathComponent) {
      $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Name)
      $candidate = (Resolve-Path -LiteralPath $providerPath -ErrorAction Stop).ProviderPath
    } else {
      $application = Get-Command -Name $Name -CommandType Application -ErrorAction Stop | Select-Object -First 1
      if ($null -eq $application -or [string]::IsNullOrWhiteSpace([string]$application.Source)) { return $null }
      $candidate = (Resolve-Path -LiteralPath $application.Source -ErrorAction Stop).ProviderPath
    }
  } catch {
    return $null
  }
  if (-not [System.IO.Path]::IsPathRooted($candidate) -or -not (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $null }
  $volumeRoot = [System.IO.Path]::GetPathRoot($candidate)
  if (Test-PathContainsReparsePoint -Path $candidate -Root $volumeRoot) { return $null }
  return $candidate
}

<#
.SYNOPSIS
  Resolves a trusted file from the Windows system directory.
.DESCRIPTION
  Validates the resolved system path before returning it to a caller.
#>
function Resolve-TrustedWindowsSystemFile {
  [CmdletBinding()]
  [OutputType([string])]
  param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$LeafName)

  if (-not $script:IsWindowsHost) { return $null }
  $systemDirectory = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System)
  if ([string]::IsNullOrWhiteSpace($systemDirectory)) { return $null }
  $candidate = Join-Path $systemDirectory $LeafName
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $null }
  $resolved = (Resolve-Path -LiteralPath $candidate -ErrorAction SilentlyContinue).ProviderPath
  if ([string]::IsNullOrWhiteSpace($resolved)) { return $null }
  $volumeRoot = [System.IO.Path]::GetPathRoot($resolved)
  if (Test-PathContainsReparsePoint -Path $resolved -Root $volumeRoot) { return $null }
  return $resolved
}

<#
.SYNOPSIS
  Resolves an approved WinGet executable path.
.DESCRIPTION
  Searches trusted locations and rejects paths that cross reparse points.
#>
function Resolve-TrustedWingetPath {
  [CmdletBinding()]
  [OutputType([string])]
  param()

  if (-not $script:IsWindowsHost) { return $null }
  $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
  if ([string]::IsNullOrWhiteSpace($programFiles)) { return $null }
  $windowsAppsRoot = Join-Path $programFiles 'WindowsApps'
  if (-not (Test-Path -LiteralPath $windowsAppsRoot -PathType Container)) { return $null }

  $candidates = New-Object System.Collections.Generic.List[string]
  try {
    foreach ($directory in @(Get-ChildItem -LiteralPath $windowsAppsRoot -Directory -Filter 'Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe' -ErrorAction Stop | Sort-Object Name -Descending)) {
      [void]$candidates.Add((Join-Path $directory.FullName 'winget.exe'))
    }
  } catch { Write-Verbose "Trusted WindowsApps enumeration failed: $($_.Exception.Message)" }

  $resolvedRoot = (Resolve-Path -LiteralPath $windowsAppsRoot -ErrorAction SilentlyContinue).ProviderPath
  foreach ($candidate in $candidates) {
    try {
      if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
      $resolved = (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).ProviderPath
      if (-not (Test-PathUnderRoot -Path $resolved -Root $resolvedRoot)) { continue }
      if (Test-PathContainsReparsePoint -Path $resolved -Root $resolvedRoot) { continue }
      return $resolved
    } catch { continue }
  }
  return $null
}

<#
.SYNOPSIS
  Resolves an approved Git executable path.
.DESCRIPTION
  Limits discovery to validated native executable locations.
#>
function Resolve-TrustedGitPath {
  [CmdletBinding()]
  [OutputType([string])]
  param()

  if (-not $script:IsWindowsHost) {
    try {
      $application = Get-Command -Name git -CommandType Application -ErrorAction Stop | Select-Object -First 1
      if ($null -eq $application -or [string]::IsNullOrWhiteSpace([string]$application.Source)) { return $null }
      $resolved = (Resolve-Path -LiteralPath $application.Source -ErrorAction Stop).ProviderPath
      $volumeRoot = [IO.Path]::GetPathRoot($resolved)
      if (Test-PathContainsReparsePoint -Path $resolved -Root $volumeRoot) { return $null }
      return $resolved
    } catch { return $null }
  }

  $roots = @(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
  foreach ($root in $roots) {
    foreach ($relativePath in @('Git\cmd\git.exe', 'Git\bin\git.exe')) {
      try {
        $candidate = Join-Path $root $relativePath
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        $resolved = (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).ProviderPath
        if (-not (Test-PathUnderRoot -Path $resolved -Root $root)) { continue }
        if (Test-PathContainsReparsePoint -Path $resolved -Root $root) { continue }
        return $resolved
      } catch { continue }
    }
  }
  return $null
}

<#
.SYNOPSIS
  Throws if a required cmdlet or function is not available.
.PARAMETER Name
  Cmdlet or function name to check.
.PARAMETER Message
  Custom error message on failure.
#>
function Ensure-Cmdlet {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Name,
    [string]$Message
  )
  if ($null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)) { return $true }
  $msg = if ($Message) { $Message } else { "Required cmdlet or function not found: $Name" }
  throw $msg
}

<#
.SYNOPSIS
  Throws if a required executable cannot be resolved through the trusted
  native-executable policy.
.PARAMETER Name
  Executable name to check.
.PARAMETER Message
  Custom error message on failure.
#>
function Ensure-Exe {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Name,
    [string]$Message
  )
  $exe = Resolve-NativeExecutablePath -Name $Name
  if (-not [string]::IsNullOrWhiteSpace($exe)) { return $true }
  $msg = if ($Message) { $Message } else { "Required executable not found: $Name" }
  throw $msg
}
