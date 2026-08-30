#requires -version 5.1
<#
.SYNOPSIS
Regression coverage for the public-surface verifier.
#>

BeforeAll {
  $verifyPath = Join-Path $PSScriptRoot '../../tools/verify.ps1'
  $tokens = $null
  $parseErrors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($verifyPath, [ref]$tokens, [ref]$parseErrors)
  $parseErrors.Count | Should -Be 0
  $publicSurfaceFunction = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -eq 'Test-PublicSurfacePath'
  }, $true)
  $script:VerifyTestModule = New-Module -Name VerifyPublicSurfaceContract -ScriptBlock ([scriptblock]::Create(
    $publicSurfaceFunction.Extent.Text + "`nExport-ModuleMember -Function Test-PublicSurfacePath"
  ))
  Import-Module $script:VerifyTestModule -Force
  $script:GitIgnoreLines = @(Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../.gitignore'))
}

AfterAll {
  Remove-Module VerifyPublicSurfaceContract -Force -ErrorAction SilentlyContinue
}

Describe 'tools/verify.ps1 secret and evidence filename policy' -Tag 'Security' {
  It 'retains every secret and evidence ignore pattern' -ForEach @('*.local', '*.local.*', '*.db', '*.sqlite', '*.sqlite3', '*.keystore') {
    $script:GitIgnoreLines | Should -Contain $_
  }

  It 'rejects secret and evidence filenames even when they are tracked' -ForEach @(
    'settings.local',
    'settings.local.production',
    'evidence.db',
    'cache.sqlite',
    'cache.sqlite3',
    'release.keystore'
  ) {
    Test-PublicSurfacePath -RelativePath $_ | Should -Be 'local secret, database, or keystore file'
  }
}
