#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for library-module contracts.

.DESCRIPTION
Verifies module behavior that security automation depends on.
#>

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Validation.psm1') -Force
}

Describe 'Test-PathTraversal' {
  It 'Returns true for traversal path' {
    Test-PathTraversal -Path '..\evil\file.txt' | Should -Be $true
  }

  It 'Returns false for safe path' {
    Test-PathTraversal -Path 'C:\Temp\safe.txt' | Should -Be $false
  }

  It 'Returns false for null or empty input' {
    Test-PathTraversal -Path $null | Should -Be $false
    Test-PathTraversal -Path '' | Should -Be $false
    Test-PathTraversal -Path '   ' | Should -Be $false
  }

  It 'Detects forward-slash traversal' {
    Test-PathTraversal -Path '../etc/passwd' | Should -Be $true
  }

  It 'Detects mid-path forward-slash traversal' {
    Test-PathTraversal -Path 'safe/../evil.txt' | Should -Be $true
  }

  It 'Detects mid-path traversal' {
    Test-PathTraversal -Path 'C:\Temp\..\Windows' | Should -Be $true
  }
}

Describe 'Test-SafeScriptName' {
  It 'Accepts numbered script names' {
    Test-SafeScriptName -Name '18-Firewall-Baseline.ps1' | Should -Be $true
  }

  It 'Rejects path components' {
    Test-SafeScriptName -Name '..\outside.ps1' | Should -Be $false
  }

  It 'Rejects unsafe characters' {
    Test-SafeScriptName -Name '18-Bad:Name.ps1' | Should -Be $false
    Test-SafeScriptName -Name '18-Bad*Name.ps1' | Should -Be $false
  }

  It 'Rejects null or empty input' {
    Test-SafeScriptName -Name $null | Should -Be $false
    Test-SafeScriptName -Name '' | Should -Be $false
    Test-SafeScriptName -Name '   ' | Should -Be $false
  }

  It 'Rejects non-.ps1 extension' {
    Test-SafeScriptName -Name '01-Script.txt' | Should -Be $false
    Test-SafeScriptName -Name '01-Script.bat' | Should -Be $false
  }

  It 'Rejects names starting with a dot' {
    Test-SafeScriptName -Name '.hidden-script.ps1' | Should -Be $false
  }

  It 'Rejects names starting with a dash' {
    Test-SafeScriptName -Name '-dangerous.ps1' | Should -Be $false
  }

  It 'Rejects names containing backslash or forward slash' {
    Test-SafeScriptName -Name 'sub/script.ps1' | Should -Be $false
    Test-SafeScriptName -Name 'sub\script.ps1' | Should -Be $false
  }

  It 'Rejects names with leading or trailing whitespace' {
    Test-SafeScriptName -Name ' script.ps1' | Should -Be $false
    Test-SafeScriptName -Name 'script.ps1 ' | Should -Be $false
  }
}

Describe 'Test-ValidGitRef' {
  It 'Accepts branch ref' {
    Test-ValidGitRef -Ref 'main' | Should -Be $true
  }

  It 'Rejects unsafe ref' {
    Test-ValidGitRef -Ref '../main' | Should -Be $false
  }

  It 'Rejects null or empty ref' {
    Test-ValidGitRef -Ref $null | Should -Be $false
    Test-ValidGitRef -Ref '' | Should -Be $false
    Test-ValidGitRef -Ref '   ' | Should -Be $false
  }

  It 'Rejects ref with double dot (..)' {
    Test-ValidGitRef -Ref 'main..branch' | Should -Be $false
  }

  It 'Rejects ref with tilde' {
    Test-ValidGitRef -Ref 'HEAD~1' | Should -Be $false
  }

  It 'Rejects ref with caret' {
    Test-ValidGitRef -Ref 'HEAD^2' | Should -Be $false
  }

  It 'Rejects ref with @{' {
    Test-ValidGitRef -Ref 'main@{0}' | Should -Be $false
  }

  It 'Rejects ref starting with dash' {
    Test-ValidGitRef -Ref '-branch' | Should -Be $false
  }

  It 'Rejects ref ending with .lock' {
    Test-ValidGitRef -Ref 'branch.lock' | Should -Be $false
  }

  It 'Rejects ref ending with dot' {
    Test-ValidGitRef -Ref 'branch.' | Should -Be $false
  }

  It 'Rejects ref ending with slash' {
    Test-ValidGitRef -Ref 'branch/' | Should -Be $false
  }

  It 'Rejects ref with backslash' {
    Test-ValidGitRef -Ref 'branch\name' | Should -Be $false
  }

  It 'Rejects ref with colon' {
    Test-ValidGitRef -Ref 'branch:name' | Should -Be $false
  }

  It 'Rejects ref with question mark' {
    Test-ValidGitRef -Ref 'branch?name' | Should -Be $false
  }

  It 'Rejects ref with asterisk' {
    Test-ValidGitRef -Ref 'branch*' | Should -Be $false
  }

  It 'Rejects ref with open bracket' {
    Test-ValidGitRef -Ref 'branch[0]' | Should -Be $false
  }

  It 'Accepts valid feature branch name' {
    Test-ValidGitRef -Ref 'feature/my-branch' | Should -Be $true
  }

  It 'Accepts valid tag format' {
    Test-ValidGitRef -Ref 'v1.2.3' | Should -Be $true
  }

  It 'Accepts ref with hyphen and numbers' {
    Test-ValidGitRef -Ref 'release-2024.01' | Should -Be $true
  }
}

Describe 'Assert-NoPathTraversal' {
  It 'Does not throw for safe path' {
    { Assert-NoPathTraversal -Path 'C:\Temp\safe.txt' } | Should -Not -Throw
  }

  It 'Throws for traversal path' {
    { Assert-NoPathTraversal -Path '..\evil\file.txt' } | Should -Throw '*path traversal*'
  }

  It 'Throws with custom parameter name in message' {
    { Assert-NoPathTraversal -Path '..\escape' -ParameterName 'ConfigPath' } | Should -Throw '*ConfigPath*'
  }
}

Describe 'Test-SafeUrl' {
  It 'Accepts https URL' {
    Test-SafeUrl -Url 'https://example.com/resource' | Should -Be $true
  }

  It 'Accepts http URL' {
    Test-SafeUrl -Url 'http://example.com/resource' | Should -Be $true
  }

  It 'Rejects file:// scheme' {
    Test-SafeUrl -Url 'file:///etc/passwd' | Should -Be $false
  }

  It 'Rejects ftp:// scheme' {
    Test-SafeUrl -Url 'ftp://evil.com/payload' | Should -Be $false
  }

  It 'Rejects null or empty' {
    Test-SafeUrl -Url $null | Should -Be $false
    Test-SafeUrl -Url '' | Should -Be $false
    Test-SafeUrl -Url '   ' | Should -Be $false
  }

  It 'Rejects argument injection via leading dash' {
    Test-SafeUrl -Url '-http://evil.com' | Should -Be $false
  }

  It 'Rejects relative URLs' {
    Test-SafeUrl -Url '/relative/path' | Should -Be $false
  }

  It 'Accepts custom allowed schemes' {
    Test-SafeUrl -Url 'ftp://example.com' -AllowedSchemes @('ftp') | Should -Be $true
  }
}

Describe 'Test-PathUnderRoot' {
  It 'treats the root directory itself as contained' {
    Test-PathUnderRoot -Path $TestDrive -Root $TestDrive | Should -BeTrue
    Test-PathUnderRoot -Path ($TestDrive + [System.IO.Path]::DirectorySeparatorChar) -Root $TestDrive | Should -BeTrue
  }

  It 'Returns true when path is under root' {
    $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
    $child = Join-Path $tempRoot 'subdir/file.txt'
    Test-PathUnderRoot -Path $child -Root $tempRoot | Should -Be $true
  }

  It 'Returns false when path escapes root' {
    $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
    $escaped = Join-Path $tempRoot '../../etc/passwd'
    Test-PathUnderRoot -Path $escaped -Root $tempRoot | Should -Be $false
  }

  It 'Returns false for a sibling directory' {
    $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
    $sibling = Join-Path (Split-Path $tempRoot -Parent) 'sibling-dir'
    Test-PathUnderRoot -Path $sibling -Root $tempRoot | Should -Be $false
  }

  It 'does not collapse case distinctions on non-Windows hosts' -Skip:([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $root = Join-Path $TestDrive 'CaseSensitiveRoot'
    $caseSibling = Join-Path $TestDrive 'casesensitiveroot/file.txt'

    Test-PathUnderRoot -Path $caseSibling -Root $root | Should -BeFalse
  }
}

Describe 'Windows privileged-path ACL validation' {
  It 'excludes inherit-only templates from current-object rights in every host build' {
    (Get-Command Test-TrustedWindowsPathAcl).Definition |
      Should -Match 'PropagationFlags\]::InheritOnly'
  }

  It 'uses the same atomic leaf write capabilities in every duplicated privileged-path guard' {
    $guards = @(
      @{ Source = (Get-Command Test-TrustedWindowsPathAcl).Definition; Terminator = '\$ancestorReplacementMask' },
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1') -Raw; Terminator = '\$ancestorReplacementMask' },
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/00-Run-Batch.ps1') -Raw; Terminator = '\$ancestorReplacementMask' },
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/00-Copy-Local.ps1') -Raw; Terminator = '\$replaceMask' },
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1') -Raw; Terminator = '\$ancestorReplacementMask' },
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/internal/16-Sysmon-Config-Updater.helpers.ps1') -Raw; Terminator = 'foreach \(\$accessRule' },
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/internal/17-Sysmon-Rule-Drift-Sensor.helpers.ps1') -Raw; Terminator = 'foreach \(\$accessRule' },
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/internal/21-EmergencyKillSwitch.helpers.ps1') -Raw; Terminator = 'foreach \(\$rule' }
    )
    $capabilities = @(
      'WriteData', 'AppendData', 'WriteExtendedAttributes', 'WriteAttributes',
      'DeleteSubdirectoriesAndFiles', 'Delete', 'ChangePermissions', 'TakeOwnership'
    )

    foreach ($guard in $guards) {
      $match = [regex]::Match($guard.Source, ('(?s)\$writeMask\s*=\s*(.*?){0}' -f $guard.Terminator))
      $match.Success | Should -BeTrue
      $leafMask = $match.Groups[1].Value
      $leafMask | Should -Not -Match 'FileSystemRights\]::(Write|Modify|FullControl)\s*-bor'
      foreach ($capability in $capabilities) {
        $leafMask | Should -Match ('FileSystemRights\]::{0}' -f $capability)
        $rights = [int64][System.Security.AccessControl.FileSystemRights]::$capability
        $readAndExecute = [int64](
          [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
          [System.Security.AccessControl.FileSystemRights]::Synchronize
        )
        ($readAndExecute -band $rights) | Should -Be 0
        ($rights -band $rights) | Should -Be $rights
      }
    }
  }

  It 'is a portable no-op on non-Windows hosts' -Skip:([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    Test-TrustedWindowsPathAcl -Path $TestDrive | Should -BeTrue
    { Assert-TrustedWindowsPathAcl -Path $TestDrive | Out-Null } | Should -Not -Throw
  }

  It 'allows effective Users ReadAndExecute but rejects an atomic Users WriteData ACE' -Skip:([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    $path = Join-Path $TestDrive 'trusted-acl'
    New-Item -Path $path -ItemType Directory -Force | Out-Null
    try {
      $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
      $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
      $users = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
      $creatorOwner = New-Object System.Security.Principal.SecurityIdentifier('S-1-3-0')
      $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
      $security = New-Object System.Security.AccessControl.DirectorySecurity
      $security.SetOwner($administrators)
      $security.SetAccessRuleProtection($true, $false)
      foreach ($sid in @($administrators, $system)) {
        [void]$security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
              $sid,
              [System.Security.AccessControl.FileSystemRights]::FullControl,
              $inheritance,
              [System.Security.AccessControl.PropagationFlags]::None,
              [System.Security.AccessControl.AccessControlType]::Allow)))
      }
      [void]$security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $creatorOwner,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::InheritOnly,
            [System.Security.AccessControl.AccessControlType]::Allow)))
      [void]$security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $users,
            ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
              [System.Security.AccessControl.FileSystemRights]::Synchronize),
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)))
      Set-Acl -LiteralPath $path -AclObject $security -ErrorAction Stop
    } catch {
      Set-ItResult -Skipped -Because "The current Windows test identity cannot create the required ACL fixture: $($_.Exception.Message)"
      return
    }

    Test-TrustedWindowsPathAcl -Path $path | Should -BeTrue
    $unsafe = Get-Acl -LiteralPath $path
    [void]$unsafe.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
          $users,
          [System.Security.AccessControl.FileSystemRights]::WriteData,
          $inheritance,
          [System.Security.AccessControl.PropagationFlags]::None,
          [System.Security.AccessControl.AccessControlType]::Allow)))
    Set-Acl -LiteralPath $path -AclObject $unsafe -ErrorAction Stop
    Test-TrustedWindowsPathAcl -Path $path | Should -BeFalse
  }
}

Describe 'Test-PathContainsReparsePoint' {
  It 'preserves the filesystem root while walking path components' {
    $volumeRoot = [System.IO.Path]::GetPathRoot($TestDrive)

    Test-PathContainsReparsePoint -Path $TestDrive -Root $volumeRoot | Should -BeFalse
  }

  It 'accepts an ordinary existing child path' {
    $root = Join-Path $TestDrive 'plain-root'
    $childDir = Join-Path $root 'child'
    $child = Join-Path $childDir 'script.ps1'
    New-Item -Path $childDir -ItemType Directory -Force | Out-Null
    Set-Content -LiteralPath $child -Value 'param()' -Encoding UTF8

    Test-PathContainsReparsePoint -Path $child -Root $root | Should -BeFalse
  }

  It 'fails closed for a missing or out-of-root path' {
    $root = Join-Path $TestDrive 'closed-root'
    New-Item -Path $root -ItemType Directory -Force | Out-Null

    Test-PathContainsReparsePoint -Path (Join-Path $root 'missing.ps1') -Root $root | Should -BeTrue
    Test-PathContainsReparsePoint -Path (Join-Path $TestDrive 'outside.ps1') -Root $root | Should -BeTrue
  }

  It 'rejects an ancestor symbolic link' {
    $root = Join-Path $TestDrive 'linked-root'
    $outside = Join-Path $TestDrive 'linked-outside'
    New-Item -Path $root -ItemType Directory -Force | Out-Null
    New-Item -Path $outside -ItemType Directory -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $outside 'script.ps1') -Value 'param()' -Encoding UTF8
    $link = Join-Path $root 'link'
    try {
      New-Item -Path $link -ItemType SymbolicLink -Target $outside -ErrorAction Stop | Out-Null
    } catch {
      Set-ItResult -Skipped -Because 'Symbolic links are not available in this environment.'
      return
    }

    Test-PathContainsReparsePoint -Path (Join-Path $link 'script.ps1') -Root $root | Should -BeTrue
  }
}

Describe 'Test-SafeOutputFilePath' {
  It 'accepts a local output path without creating missing parents' {
    $path = Join-Path $TestDrive 'output/nested/report.csv'

    Test-SafeOutputFilePath -Path $path | Should -BeTrue
    Test-Path -LiteralPath ([System.IO.Path]::GetDirectoryName($path)) | Should -BeFalse
  }

  It 'creates missing parents through the explicit initializer' {
    $path = Join-Path $TestDrive 'output/nested/report.csv'

    Initialize-SafeOutputFilePath -Path $path | Should -BeTrue
    Test-Path -LiteralPath ([System.IO.Path]::GetDirectoryName($path)) | Should -BeTrue
  }

  It 'rejects traversal and UNC output paths' {
    Test-SafeOutputFilePath -Path '../escape.csv' | Should -BeFalse
    Test-SafeOutputFilePath -Path '\\server\share\report.csv' | Should -BeFalse
  }

  It 'rejects a reparse-point ancestor' -Skip:([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    $root = Join-Path $TestDrive 'output-link-root'
    $outside = Join-Path $TestDrive 'output-link-outside'
    New-Item -Path $root -ItemType Directory -Force | Out-Null
    New-Item -Path $outside -ItemType Directory -Force | Out-Null
    $link = Join-Path $root 'link'
    try {
      New-Item -Path $link -ItemType SymbolicLink -Target $outside -ErrorAction Stop | Out-Null
    } catch {
      Set-ItResult -Skipped -Because 'Symbolic links are not available in this environment.'
      return
    }

    Test-SafeOutputFilePath -Path (Join-Path $link 'report.csv') | Should -BeFalse
  }
}

Describe 'Test-WingetPrivateSourceDefinition' {
  It 'allows explicitly supported source types on public HTTPS endpoints' -ForEach @('Microsoft.Rest', 'Microsoft.PreIndexed.Package') {
    Test-WingetPrivateSourceDefinition -Url 'https://packages.example.com/cache' -Type $_ | Should -BeTrue
  }

  It 'rejects unsupported types and unsafe endpoint forms' -ForEach @(
    @{ Url = 'https://packages.example.com/cache'; Type = 'Microsoft.SQLite' }
    @{ Url = 'http://packages.example.com/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://user:password@packages.example.com/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://packages.example.com/cache?access_token=secret'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://packages.example.com/cache#access_token=secret'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://localhost/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://repo.local/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://127.0.0.1/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://169.254.1.1/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://[fe80::1]/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://[fc00::1]/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://[::ffff:127.0.0.1]/cache'; Type = 'Microsoft.Rest' }
  ) {
    Test-WingetPrivateSourceDefinition -Url $Url -Type $Type | Should -BeFalse
  }
}

Describe 'Get-BoundedUtf8FileContent' {
  It 'reads ordinary UTF-8 content and exposes a stable content hash' {
    $path = Join-Path $TestDrive 'bounded.json'
    [System.IO.File]::WriteAllText($path, '{"value":1}', (New-Object System.Text.UTF8Encoding($false)))

    $text = Get-BoundedUtf8FileContent -Path $path -MaximumBytes 1024

    $text | Should -Be '{"value":1}'
    Get-TextSha256 -Text $text | Should -Match '^[A-F0-9]{64}$'
  }

  It 'rejects an oversized file before reading it' {
    $path = Join-Path $TestDrive 'oversized.json'
    [System.IO.File]::WriteAllBytes($path, ([byte[]](1..32)))

    { Get-BoundedUtf8FileContent -Path $path -MaximumBytes 16 } | Should -Throw '*size limit*'
  }

  It 'rejects invalid UTF-8' {
    $path = Join-Path $TestDrive 'invalid-utf8.json'
    [System.IO.File]::WriteAllBytes($path, [byte[]](0xC3, 0x28))

    { Get-BoundedUtf8FileContent -Path $path -MaximumBytes 16 } | Should -Throw
  }
}
