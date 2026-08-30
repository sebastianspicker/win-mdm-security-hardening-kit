#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for the WinGet audit/remediation boundary.

.DESCRIPTION
Verifies that audit mode remains observational and that configuration needed
only to add a missing source is not required when checking an existing source.
#>

BeforeAll {
  $script:ScriptPath = Join-Path $PSScriptRoot '../../scripts/08-WinGet-SelfHeal.ps1'
  $script:Tokens = $null
  $script:ParseErrors = $null
  $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $script:ScriptPath,
    [ref]$script:Tokens,
    [ref]$script:ParseErrors
  )
  $script:ScriptSource = Get-Content -LiteralPath $script:ScriptPath -Raw

  $ensureFunction = $script:Ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -eq 'Ensure-PrivateSource'
  }, $true)
  $sourceOutputFunction = $script:Ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -eq 'Test-WingetSourceOutputContainsName'
  }, $true)
  $processMetadataFunction = $script:Ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -eq 'Protect-WingetProcessMetadata'
  }, $true)
  $privateSourceMetadataFunction = $script:Ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -eq 'Get-PrivateSourceResultMetadata'
  }, $true)
  $invokeWingetFunction = $script:Ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -eq 'Invoke-Winget'
  }, $true)

  $testModuleSource = @'
$script:SourcePresent = $true
$script:AddCalls = 0
$script:NativeStdOut = ''
$script:NativeStdErr = ''

function Test-WingetSourcePresent {
  param([string]$WingetPath, [string]$Name)
  return $script:SourcePresent, 'test detail'
}

function Test-WingetPrivateSourceDefinition {
  param([string]$Url, [string]$Type)
  return $false
}

function Invoke-NativeCommand {
  param([string]$Command, [string[]]$Arguments)
  $script:AddCalls++
  return [pscustomobject]@{
    ExitCode = 0
    StdErr = $script:NativeStdErr
    StdOut = $script:NativeStdOut
    TimedOut = $false
    OutputTruncated = $false
    StderrTruncated = $false
    Success = $true
  }
}

function Set-WingetSourceTestState {
  param([bool]$Present)
  $script:SourcePresent = $Present
  $script:AddCalls = 0
}

function Set-WingetProcessTestOutput {
  param([string]$StdOut, [string]$StdErr)
  $script:NativeStdOut = $StdOut
  $script:NativeStdErr = $StdErr
}

function Get-WingetSourceTestState {
  [pscustomobject]@{ AddCalls = $script:AddCalls }
}
'@
  $testModuleSource += "`n" + $processMetadataFunction.Extent.Text
  $testModuleSource += "`n" + $privateSourceMetadataFunction.Extent.Text
  $testModuleSource += "`n" + $invokeWingetFunction.Extent.Text
  $testModuleSource += "`n" + $ensureFunction.Extent.Text
  $testModuleSource += "`n" + $sourceOutputFunction.Extent.Text
  $testModuleSource += "`nExport-ModuleMember -Function Ensure-PrivateSource,Test-WingetSourceOutputContainsName,Invoke-Winget,Get-PrivateSourceResultMetadata,Set-WingetSourceTestState,Set-WingetProcessTestOutput,Get-WingetSourceTestState"
  $script:WinGetTestModule = New-Module -Name WinGetSelfHealContract -ScriptBlock ([scriptblock]::Create($testModuleSource))
  Import-Module $script:WinGetTestModule -Force
}

AfterAll {
  Remove-Module WinGetSelfHealContract -Force -ErrorAction SilentlyContinue
}

Describe 'WinGet audit boundary' {
  It 'checks an existing private source without requiring add-only configuration' {
    Set-WingetSourceTestState -Present $true

    $present, $detail = Ensure-PrivateSource -WingetPath 'winget.exe' -Name 'corp' -DoIt:$false

    $present | Should -BeTrue
    $detail | Should -Be 'Present'
    (Get-WingetSourceTestState).AddCalls | Should -Be 0
  }

  It 'does not attempt to add a missing source in audit mode' {
    Set-WingetSourceTestState -Present $false

    $present, $detail = Ensure-PrivateSource -WingetPath 'winget.exe' -Name 'corp' -Url 'not-a-url' -Type 'unsupported' -DoIt:$false

    $present | Should -BeFalse
    $detail | Should -Match '^Missing \(no remediation\)'
    (Get-WingetSourceTestState).AddCalls | Should -Be 0
  }

  It 'guards every source update behind remediation mode and ShouldProcess' {
    $updateCalls = @($script:Ast.FindAll({
      param($node)
      $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Invoke-WingetSourceUpdate'
    }, $true))

    $updateCalls.Count | Should -Be 1
    foreach ($call in $updateCalls) {
      $ancestor = $call.Parent
      $remediationGuarded = $false
      $shouldProcessGuarded = $false
      while ($null -ne $ancestor) {
        if ($ancestor -is [System.Management.Automation.Language.IfStatementAst] -and
            $ancestor.Extent.Text -match 'if\s*\(\$wg\s+-and\s+\$Remediate\)') {
          $remediationGuarded = $true
        }
        if ($ancestor -is [System.Management.Automation.Language.IfStatementAst] -and
            $ancestor.Extent.Text -match '\$PSCmdlet\.ShouldProcess') {
          $shouldProcessGuarded = $true
        }
        $ancestor = $ancestor.Parent
      }
      $remediationGuarded | Should -BeTrue
      $shouldProcessGuarded | Should -BeTrue
    }
  }

  It 'does not let wrapper configuration grant remediation authority' {
    $script:ScriptSource | Should -Not -Match 'Get-NestedPropValue\s+-Object\s+\$cfg\s+-Path\s+@\(''VCppRedist'''
    $script:ScriptSource | Should -Not -Match 'Get-NestedPropValue\s+-Object\s+\$cfg\s+-Path\s+@\(''Winget'',''PrivateSourceUrl'''
    $script:ScriptSource | Should -Match 'PSBoundParameters\.ContainsKey\(''PrivateSourceName''\)'
    $script:ScriptSource | Should -Match 'PSBoundParameters\.ContainsKey\(''PrivateSourceUrl''\)'
  }

  It 'requires endpoint-only private-source URLs and out-of-band authentication' {
    $script:ScriptSource | Should -Match 'without credentials, query, or fragment'
    $script:ScriptSource | Should -Match 'Configure source authentication out of band'
  }

  It 'redacts credential-bearing URLs from WinGet process metadata' {
    $credentialUrl = 'https://operator:do-not-log@packages.example.test/cache'
    $queryUrl = 'https://packages.example.test/cache?access_token=do-not-log'
    Set-WingetProcessTestOutput -StdOut "Source $credentialUrl" -StdErr "Failed $queryUrl"

    $result = Invoke-Winget -WingetPath 'winget.exe' -WingetArgs @('source', 'add', '-a', $credentialUrl, '--legacy', $queryUrl)
    $metadata = $result | ConvertTo-Json -Depth 4 -Compress

    $metadata | Should -Not -Match ([regex]::Escape($credentialUrl))
    $metadata | Should -Not -Match ([regex]::Escape($queryUrl))
    $metadata | Should -Match '\[credential-bearing URL redacted\]'
  }

  It 'omits the private-source endpoint from structured result metadata' {
    $credentialUrl = 'https://operator:do-not-log@packages.example.test/cache'
    $metadata = Get-PrivateSourceResultMetadata -Name 'corp' -Type 'Microsoft.Rest'

    $metadata.ContainsKey('Url') | Should -BeFalse
    $metadata.Endpoint | Should -Be '[not recorded]'
    ($metadata | ConvertTo-Json -Compress) | Should -Not -Match ([regex]::Escape($credentialUrl))
  }

  It 'requires positive source identity evidence' {
    $sourceFunction = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Test-WingetSourcePresent'
    }, $true)

    $sourceFunction.Extent.Text | Should -Not -Match 'assumed present'
    $sourceFunction.Extent.Text | Should -Match 'Test-WingetSourceOutputContainsName'
  }

  It 'matches only the exact WinGet source name' {
    Test-WingetSourceOutputContainsName -Text "Name Argument`ncorp https://packages.example.test" -Name 'corp' | Should -BeTrue
    Test-WingetSourceOutputContainsName -Text 'Name: CORP' -Name 'corp' | Should -BeTrue
    Test-WingetSourceOutputContainsName -Text 'corporate https://packages.example.test' -Name 'corp' | Should -BeFalse
    Test-WingetSourceOutputContainsName -Text 'corp-prod https://packages.example.test' -Name 'corp' | Should -BeFalse
    Test-WingetSourceOutputContainsName -Text 'mycorp https://packages.example.test' -Name 'corp' | Should -BeFalse
  }
}
