<#
.SYNOPSIS
Input validation and security guard functions.

.DESCRIPTION
Provides functions to detect path traversal, validate script names, git refs,
URLs, and directory containment. Used across scripts to enforce input safety.
#>

Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Tests whether a path contains traversal segments ('..').
.PARAMETER Path
  Path string to check.
#>
function Test-PathTraversal {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Path
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    return $false
  }

  $normalized = $Path.Replace('/', '\')
  if ($normalized -match '(^|\\)\.\.(\\|$)') { return $true }
  if ($normalized -match '\\.\\.\\') { return $true }
  return $false
}

<#
.SYNOPSIS
  Throws if a path contains traversal segments.
.PARAMETER Path
  Path string to validate.
.PARAMETER ParameterName
  Name shown in the error message (default 'Path').
#>
function Assert-NoPathTraversal {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Path,
    [string]$ParameterName = 'Path'
  )

  if (Test-PathTraversal -Path $Path) {
    throw "$ParameterName must not contain path traversal segments ('..')."
  }
}

<#
.SYNOPSIS
  Validates that a script name is safe (no path separators, valid .ps1 extension).
.PARAMETER Name
  Script file name to validate.
#>
function Test-SafeScriptName {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Name
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
  if ($Name -match '[\\/]') { return $false }
  if (Test-PathTraversal -Path $Name) { return $false }
  if ($Name -match '[\x00-\x1F]') { return $false }
  if ($Name -match '[:*?"<>|]') { return $false }
  if ($Name -match '^\s|\s$') { return $false }
  $ext = [System.IO.Path]::GetExtension($Name)
  if ($ext -ne '.ps1') { return $false }
  if ($Name -match '^[.-]') { return $false }
  return $true
}

<#
.SYNOPSIS
  Validates that a string is a safe git ref (branch/tag name).
.PARAMETER Ref
  Git ref string to validate.
#>
function Test-ValidGitRef {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Ref
  )

  if ([string]::IsNullOrWhiteSpace($Ref)) { return $false }
  if ($Ref -match '^\s*-') { return $false }
  if ($Ref -match '\.\.') { return $false }
  if ($Ref -match '[~^:\?*\[\\]') { return $false }
  if ($Ref -match '@\{') { return $false }
  if ($Ref.EndsWith('.') -or $Ref.EndsWith('/') -or $Ref.EndsWith('.lock')) { return $false }
  return $true
}

<#
.SYNOPSIS
  Validates that a URL uses an allowed scheme and is well-formed.
.PARAMETER Url
  URL string to validate.
.PARAMETER AllowedSchemes
  Permitted URI schemes (default: https, http).
#>
function Test-SafeUrl {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Url,
    [string[]]$AllowedSchemes = @('https', 'http')
  )

  if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
  if ($Url -match '^\s*-') { return $false }

  $uri = $null
  if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri)) {
    return $false
  }

  if (-not $AllowedSchemes -or $AllowedSchemes.Count -eq 0) {
    return $true
  }

  return ($AllowedSchemes -contains $uri.Scheme)
}

<#
.SYNOPSIS
  Tests whether a path is contained within a root directory.
.PARAMETER Path
  Path to check.
.PARAMETER Root
  Root directory that must be a prefix of Path.
#>
function Test-PathUnderRoot {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Path,
    [Parameter(Mandatory)]
    [string]$Root
  )

  try {
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    $rootFull = [System.IO.Path]::GetFullPath($Root)
  } catch {
    return $false
  }

  $sep = [System.IO.Path]::DirectorySeparatorChar
  $comparison = if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    [System.StringComparison]::OrdinalIgnoreCase
  } else {
    [System.StringComparison]::Ordinal
  }
  $volumeRoot = [System.IO.Path]::GetPathRoot($rootFull)
  $rootNormalized = if ($rootFull.Length -gt $volumeRoot.Length) { $rootFull.TrimEnd($sep) } else { $rootFull }
  $pathNormalized = if ($pathFull.Length -gt ([System.IO.Path]::GetPathRoot($pathFull)).Length) { $pathFull.TrimEnd($sep) } else { $pathFull }
  if ($pathNormalized.Equals($rootNormalized, $comparison)) { return $true }
  $rootPrefix = $rootNormalized.TrimEnd($sep) + $sep
  return $pathNormalized.StartsWith($rootPrefix, $comparison)
}

<#
.SYNOPSIS
  Tests whether a Windows filesystem path is protected from untrusted writers.
.DESCRIPTION
  Uses stable SIDs rather than localized account names. The protected path must
  be owned by, and grant write-capable access only to, SYSTEM, BUILTIN\Administrators,
  or Windows Modules Installer (TrustedInstaller). Optional ancestor checks
  reject an untrusted principal that can delete/replace a protected descendant.
  Non-Windows hosts return true so portable parsing and unit tests remain usable.
#>
function Test-TrustedWindowsPathAcl {
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$CheckAncestors
  )

  if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    return $true
  }

  $trustedSids = @{
    'S-1-5-18' = $true # LOCAL SYSTEM
    'S-1-5-32-544' = $true # BUILTIN\Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' = $true # TrustedInstaller
  }
  $writeMask =
    [System.Security.AccessControl.FileSystemRights]::WriteData -bor
    [System.Security.AccessControl.FileSystemRights]::AppendData -bor
    [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
  $ancestorReplacementMask =
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership

  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $protectedPath = $item.FullName
    $current = $protectedPath
    $isProtectedItem = $true
    while (-not [string]::IsNullOrWhiteSpace($current)) {
      $currentItem = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        return $false
      }

      $acl = Get-Acl -LiteralPath $currentItem.FullName -ErrorAction Stop
      $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
      if (-not $trustedSids.ContainsKey($ownerSid)) {
        return $false
      }

      $effectiveMask = if ($isProtectedItem) { $writeMask } else { $ancestorReplacementMask }
      $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
      foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        # An inherit-only ACE is a template for descendants and grants no
        # rights on the object whose ACL is currently being evaluated.
        if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        $sid = [string]$rule.IdentityReference.Value
        if ($trustedSids.ContainsKey($sid)) { continue }
        if (([int64]$rule.FileSystemRights -band [int64]$effectiveMask) -ne 0) {
          return $false
        }
      }

      if (-not $CheckAncestors) { break }
      $parent = Split-Path -Parent $currentItem.FullName
      if ([string]::IsNullOrWhiteSpace($parent) -or
          [string]::Equals($parent, $currentItem.FullName, [System.StringComparison]::OrdinalIgnoreCase)) {
        break
      }
      $current = $parent
      $isProtectedItem = $false
    }
    return $true
  } catch {
    Write-Verbose ("Windows ACL validation failed for '{0}': {1}" -f $Path, $_.Exception.Message)
    return $false
  }
}

<#
.SYNOPSIS
  Throws when a Windows path does not have a trusted ACL.
.DESCRIPTION
  Applies the shared ACL validation so security-sensitive callers fail closed.
#>
function Assert-TrustedWindowsPathAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$CheckAncestors
  )

  if (-not (Test-TrustedWindowsPathAcl -Path $Path -CheckAncestors:$CheckAncestors)) {
    throw "Path ACL is not trusted for privileged execution: $Path"
  }
  return (Get-Item -LiteralPath $Path -Force -ErrorAction Stop)
}

<#
.SYNOPSIS
  Tests whether a root or any path component beneath it is a reparse point.
.DESCRIPTION
  Walks the lexical root-to-leaf path instead of checking only the final item.
  Missing, invalid, or out-of-root paths return true so callers fail closed.
.PARAMETER Path
  Existing path to inspect.
.PARAMETER Root
  Existing trusted root containing Path.
#>
function Test-PathContainsReparsePoint {
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Root
  )

  try {
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    $rootFull = [System.IO.Path]::GetFullPath($Root)
  } catch {
    return $true
  }

  if (-not (Test-PathUnderRoot -Path $pathFull -Root $rootFull)) {
    return $true
  }

  $separatorChars = @(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar
  )
  $volumeRoot = [System.IO.Path]::GetPathRoot($rootFull)
  $rootNormalized = $rootFull
  while (
    $rootNormalized.Length -gt $volumeRoot.Length -and
    $separatorChars -contains $rootNormalized[$rootNormalized.Length - 1]
  ) {
    $rootNormalized = $rootNormalized.Substring(0, $rootNormalized.Length - 1)
  }
  try {
    $rootItem = Get-Item -LiteralPath $rootNormalized -Force -ErrorAction Stop
    if ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
      return $true
    }

    $relativePath = $pathFull.Substring($rootNormalized.Length).TrimStart($separatorChars)
    $currentPath = $rootNormalized
    foreach ($segment in @($relativePath -split '[/\\]' | Where-Object { $_ })) {
      $currentPath = Join-Path $currentPath $segment
      $item = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
      if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        return $true
      }
    }
  } catch {
    return $true
  }

  return $false
}

<#
.SYNOPSIS
  Tests whether a local output-file path is safe to create or overwrite.
.DESCRIPTION
  Rejects traversal, UNC/device paths, directories, and existing reparse
  points. For a new file it validates the nearest existing parent. This
  predicate never creates directories or otherwise changes filesystem state.
#>
function Test-SafeOutputFilePath {
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [Parameter(Mandatory)][string]$Path
  )

  if ([string]::IsNullOrWhiteSpace($Path) -or (Test-PathTraversal -Path $Path)) {
    return $false
  }
  # Network shares and Win32 device namespaces can redirect a privileged
  # writer outside the local filesystem policy.
  if ($Path -match '^[\\/]{2}') {
    return $false
  }

  try {
    $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if ($providerPath -match '^[\\/]{2}') {
      return $false
    }
    $fullPath = [System.IO.Path]::GetFullPath($providerPath)
    $parentPath = [System.IO.Path]::GetDirectoryName($fullPath)
    if ([string]::IsNullOrWhiteSpace($parentPath)) {
      return $false
    }

    if (Test-Path -LiteralPath $fullPath) {
      $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
      if ($item.PSIsContainer) {
        return $false
      }
      if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        return $true
      }
      $root = [System.IO.Path]::GetPathRoot($fullPath)
      return -not (Test-PathContainsReparsePoint -Path $fullPath -Root $root)
    }

    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
      return $true
    }

    $existingParent = $parentPath
    while (-not (Test-Path -LiteralPath $existingParent -PathType Container)) {
      $nextParent = [System.IO.Path]::GetDirectoryName($existingParent)
      if ([string]::IsNullOrWhiteSpace($nextParent) -or $nextParent -eq $existingParent) {
        return $false
      }
      $existingParent = $nextParent
    }
    $root = [System.IO.Path]::GetPathRoot($existingParent)
    if (Test-PathContainsReparsePoint -Path $existingParent -Root $root) {
      return $false
    }

  } catch {
    return $false
  }

  return $true
}

<#
.SYNOPSIS
  Validates an output path and creates its parent directory when necessary.
.DESCRIPTION
  Performs pure validation before creation and repeats validation afterward so
  callers do not write through traversal, network, device, or reparse paths.
#>
function Initialize-SafeOutputFilePath {
  [CmdletBinding()]
  [OutputType([bool])]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-SafeOutputFilePath -Path $Path)) {
    return $false
  }

  try {
    $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $fullPath = [System.IO.Path]::GetFullPath($providerPath)
    $parentPath = [System.IO.Path]::GetDirectoryName($fullPath)
    if (-not (Test-Path -LiteralPath $parentPath -PathType Container)) {
      [void][System.IO.Directory]::CreateDirectory($parentPath)
    }
  } catch {
    return $false
  }

  return (Test-SafeOutputFilePath -Path $Path)
}

<#
.SYNOPSIS
  Tests a WinGet private-source type and endpoint against the local policy.
.DESCRIPTION
  The endpoint must be absolute HTTPS with a path only: credentials, query,
  and fragment components are not permitted. Configure private-source
  authentication out of band through the organization-managed WinGet or OS
  credential mechanism. The endpoint must not name a local, loopback,
  wildcard, or link-local address. DNS is deliberately not resolved here so
  validation does not introduce a network side effect.
#>
function Test-WingetPrivateSourceDefinition {
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [AllowNull()][string]$Url,
    [AllowNull()][string]$Type
  )

  $supportedTypes = @('Microsoft.Rest', 'Microsoft.PreIndexed.Package')
  if ([string]::IsNullOrWhiteSpace($Url) -or $Type -notin $supportedTypes) {
    return $false
  }

  $uri = $null
  if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri) -or
      -not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or
      -not [string]::IsNullOrWhiteSpace($uri.UserInfo) -or
      -not [string]::IsNullOrWhiteSpace($uri.Query) -or
      -not [string]::IsNullOrWhiteSpace($uri.Fragment)) {
    return $false
  }
  $sourceHost = $uri.Host.TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($sourceHost) -or $sourceHost -eq 'localhost' -or $sourceHost.EndsWith('.local', [System.StringComparison]::OrdinalIgnoreCase)) {
    return $false
  }
  $address = $null
  if ([System.Net.IPAddress]::TryParse($sourceHost, [ref]$address)) {
    if ([System.Net.IPAddress]::IsLoopback($address) -or
        $address.Equals([System.Net.IPAddress]::Any) -or
        $address.Equals([System.Net.IPAddress]::IPv6Any) -or
        $address.IsIPv6LinkLocal) {
      return $false
    }
    $bytes = $address.GetAddressBytes()
    if ($bytes.Length -eq 16 -and (($bytes[0] -band 0xFE) -eq 0xFC)) {
      return $false
    }
    $isIpv4Mapped = $bytes.Length -eq 16 -and $bytes[10] -eq 0xFF -and $bytes[11] -eq 0xFF
    if ($isIpv4Mapped) {
      foreach ($index in 0..9) {
        if ($bytes[$index] -ne 0) {
          $isIpv4Mapped = $false
          break
        }
      }
    }
    if ($isIpv4Mapped) {
      $bytes = $bytes[12..15]
    }
    if ($bytes.Length -eq 4 -and (($bytes[0] -eq 10) -or ($bytes[0] -eq 127) -or
          ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
          ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
          ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31))) {
      return $false
    }
  }
  return $true
}

<#
.SYNOPSIS
  Reads a UTF-8 text file through a stable, size-bounded file handle.
.DESCRIPTION
  Opens the file with read-only sharing so it cannot be replaced or modified
  while its size is checked and its text is consumed. Invalid UTF-8 fails
  closed instead of being silently replaced.
#>
function Get-BoundedUtf8FileContent {
  [CmdletBinding()]
  [OutputType([string])]
  param(
    [Parameter(Mandatory)][string]$Path,
    [ValidateRange(1, 16777216)][int64]$MaximumBytes = 1048576
  )

  $stream = $null
  $reader = $null
  try {
    $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (-not (Test-Path -LiteralPath $providerPath -PathType Leaf)) {
      throw "File not found: $Path"
    }
    $stream = [System.IO.File]::Open(
      $providerPath,
      [System.IO.FileMode]::Open,
      [System.IO.FileAccess]::Read,
      [System.IO.FileShare]::Read
    )
    if ($stream.Length -gt $MaximumBytes) {
      throw "File exceeds the $MaximumBytes byte size limit."
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $reader = New-Object System.IO.StreamReader($stream, $utf8, $true)
    return $reader.ReadToEnd()
  } finally {
    if ($null -ne $reader) { $reader.Dispose() }
    elseif ($null -ne $stream) { $stream.Dispose() }
  }
}

<#
.SYNOPSIS
  Computes the SHA-256 hash of text.
.DESCRIPTION
  Uses a deterministic UTF-8 representation for integrity comparisons.
#>
function Get-TextSha256 {
  [CmdletBinding()]
  [OutputType([string])]
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = (New-Object System.Text.UTF8Encoding($false, $true)).GetBytes($Text)
    return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '')
  } finally {
    $sha.Dispose()
  }
}

Export-ModuleMember -Function `
  Test-PathTraversal, `
  Assert-NoPathTraversal, `
  Test-SafeScriptName, `
  Test-ValidGitRef, `
  Test-SafeUrl, `
  Test-PathUnderRoot, `
  Test-PathContainsReparsePoint, `
  Test-SafeOutputFilePath, `
  Initialize-SafeOutputFilePath, `
  Test-WingetPrivateSourceDefinition, `
  Test-TrustedWindowsPathAcl, `
  Assert-TrustedWindowsPathAcl, `
  Get-BoundedUtf8FileContent, `
  Get-TextSha256
