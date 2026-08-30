#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

Describe 'v2 parameter contract' {
  $scriptFiles = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../../scripts') -Filter '*.ps1' -File |
    Where-Object { $_.Name -match '^\d{2}-' }
  $cases = @($scriptFiles | ForEach-Object { [pscustomobject]@{ Name = $_.Name; FullName = $_.FullName } })

  $requiredParams = @(
    'Mode',
    'ConfigPath',
    'OutputFormat',
    'OutputPath',
    'PassThru',
    'Strict',
    'Quiet',
    'NoColor'
  )

  It '<_.Name> exposes required v2 params' -ForEach $cases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $ast.ParamBlock | Should -Not -BeNullOrEmpty

    $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    foreach ($required in $requiredParams) {
      ($paramNames -contains $required) | Should -BeTrue
    }
  }

  It '<_.Name> does not expose legacy Remediate parameter' -ForEach $cases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    ($paramNames -contains 'Remediate') | Should -BeFalse
  }

  It '<_.Name> does not use legacy AuditOnly mode value' -ForEach $cases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $modeParameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Mode' } | Select-Object -First 1
    $modeValidateSet = $modeParameter.Attributes |
      Where-Object { $_.TypeName.FullName -eq 'ValidateSet' } |
      Select-Object -First 1
    ($null -eq $modeValidateSet -or (@($modeValidateSet.PositionalArguments.Value) -notcontains 'AuditOnly')) | Should -BeTrue
  }

  It '<_.Name> does not define parameter names that collide with parameter aliases' -ForEach $cases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty

    $params = @($ast.ParamBlock.Parameters)
    $paramNames = @($params | ForEach-Object { $_.Name.VariablePath.UserPath })
    $aliases = @(
      foreach ($param in $params) {
        foreach ($attr in @($param.Attributes | Where-Object { $_.TypeName.FullName -eq 'Alias' })) {
          foreach ($arg in @($attr.PositionalArguments)) {
            [string]$arg.SafeGetValue()
          }
        }
      }
    )

    @($paramNames | Where-Object { $aliases -contains $_ }) | Should -BeNullOrEmpty
  }

  It '<_.Name> enforces ShouldProcess when Mode supports Remediate' -ForEach $cases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    if (-not ($paramNames -contains 'Mode')) {
      Set-ItResult -Skipped -Because 'Script has no Mode parameter.'
      return
    }

    $modeParameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Mode' } | Select-Object -First 1
    $modeValidateSet = $modeParameter.Attributes |
      Where-Object { $_.TypeName.FullName -eq 'ValidateSet' } |
      Select-Object -First 1

    $supportsRemediate = $false
    if ($modeValidateSet) {
      $supportsRemediate = @($modeValidateSet.PositionalArguments.Value) -contains 'Remediate'
    }

    if (-not $supportsRemediate) {
      Set-ItResult -Skipped -Because 'Mode does not support Remediate.'
      return
    }

    $content = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
    ($content -match 'SupportsShouldProcess\s*=\s*\$true') | Should -BeTrue
  }

  It 'Audited scripts do not expose stale legacy Remediate help text in the top comment block' {
    $scriptsPath = Join-Path $PSScriptRoot '../../scripts'
    $legacyHelpCases = Get-ChildItem -Path $scriptsPath -File |
      Where-Object { $_.Name -match '^\d{2}-' } |
      Where-Object {
        $errors = $null
        $tokens = $null
      $null = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
        if ($errors) { return $false }

        $content = Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8
        $helpBlock = [regex]::Match($content, '(?s)<#.*?#>').Value
        $helpBlock -match '\.PARAMETER\s+Remediate|-Remediate\b'
      } |
      Select-Object -ExpandProperty Name

    foreach ($name in $legacyHelpCases) {
      $path = Join-Path $scriptsPath $name
      $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8
      $helpBlock = [regex]::Match($content, '(?s)<#.*?#>').Value

      $helpBlock | Should -Not -Match '\.PARAMETER\s+Remediate'
      $helpBlock | Should -Not -Match '-Remediate\b'
    }
  }

  It 'Scripts with filtered finding counts force array semantics before reading Count' {
    foreach ($name in @('47-WDAG-Readiness-Audit.ps1', '49-DriverSigning-Integrity-Audit.ps1')) {
      $path = Join-Path (Join-Path $PSScriptRoot '../../scripts') $name
      $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

      $content | Should -Match '@\(\$Findings \| Where-Object \{ \$_.Severity -eq ''High'' \}\)\.Count'
      $content | Should -Match '@\(\$Findings \| Where-Object \{ \$_.Severity -eq ''Medium'' \}\)\.Count'
    }
  }

  It '27-Defender-Health-Audit permits an omitted SettingsJsonPath during config load' {
    $path = Join-Path $PSScriptRoot '../../scripts/27-Defender-Health-Audit.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\[AllowEmptyString\(\)\]\s*\[string\]\$Path'
  }

  It '17-Sysmon-Rule-Drift-Sensor classifies runtime errors as FAIL' {
    $path = Join-Path $PSScriptRoot '../../scripts/17-Sysmon-Rule-Drift-Sensor.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$final\.Status\s+-in\s+@\(''FAIL'',\s*''ERROR''\)'
  }

  It '17-Sysmon-Rule-Drift-Sensor locks every platform implementation loaded by External.psm1' {
    $repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).ProviderPath
    $updaterPath = Join-Path $repositoryRoot 'scripts/16-Sysmon-Config-Updater.ps1'
    . (Join-Path $repositoryRoot 'scripts/internal/17-Sysmon-Rule-Drift-Sensor.helpers.ps1')

    $actualPlatformClosure = @(
      Get-SysmonRemediationExecutionClosure -ScriptPath $updaterPath |
        Where-Object { $_ -like (Join-Path $repositoryRoot 'lib/platform/*') }
    )
    $expectedPlatformClosure = @(
      'Executable.ps1',
      'NativeProcess.ps1',
      'NativeTools.ps1',
      'WindowsOperations.ps1'
    ) | ForEach-Object { Join-Path $repositoryRoot (Join-Path 'lib/platform' $_) }

    $actualPlatformClosure | Should -HaveCount $expectedPlatformClosure.Count
    for ($index = 0; $index -lt $expectedPlatformClosure.Count; $index++) {
      $actualPlatformClosure[$index] | Should -BeExactly $expectedPlatformClosure[$index]
    }
  }

  It 'advertised Strict has terminal WARN-to-FAIL handling in audited scripts' {
    $strictPaths = @(
      '00-Copy-Local.ps1', '00-Report-Aggregate.ps1', '00-Run-Local.ps1', '00-Validate-Profile.ps1',
      '01-ASR-Defender-Allowlist.ps1', '02-LAPS-Hygiene.ps1', '03-LocalAdmins-Guardrail.ps1',
      '10-SupportBundle-Parser.ps1', '25-WinGet-Config-Baseline-Runner.ps1', '26-Get-WinEvent-FastTriage.ps1',
      '29-Network-Config-Audit.ps1', '30-Service-Process-Audit.ps1', '42-Client-SecurityBaseline-Report-IntuneRef.ps1'
    )
    foreach ($name in $strictPaths) {
      $content = Get-Content -LiteralPath (Join-Path $PSScriptRoot "../../scripts/$name") -Raw -Encoding UTF8
      $content | Should -Match '\[switch\]\$Strict'
      $content | Should -Match '\$Strict\s*-and\s+\$\w+\s+-eq\s+''WARN''|if\s*\(\$Strict\)\s*\{\s*(?:\$\w+\s*=\s*)?''FAIL''\s*\}'
    }
  }
}

Describe 'migrated v2 initialization runtime smoke' {
  $migratedInitCases = @(
    @{ Name = '47-WDAG-Readiness-Audit.ps1'; Path = (Join-Path $PSScriptRoot '../../scripts/47-WDAG-Readiness-Audit.ps1') }
  )

  It '<_.Name> preserves v2 output switches after Initialize-V2Context migration' -ForEach $migratedInitCases {
    $case = $_
    if ($env:OS -eq 'Windows_NT') {
      Set-ItResult -Skipped -Because 'Smoke uses the unsupported-host branch to avoid Windows provider side effects.'
      return
    }

    $result = & $case.Path -OutputFormat None -PassThru -Strict:$false -Quiet -NoColor
    $exitCode = $LASTEXITCODE

    $exitCode | Should -Be 2
    $result.Result | Should -Be 'WARN'
    $result.ScriptName | Should -Be $case.Name
    $result.Mode | Should -Be 'Audit'
    $result.Summary.Mode | Should -Be 'Audit'
    $result.Summary.Supported | Should -BeFalse
    $result.Metadata.UnsupportedHost | Should -BeTrue
  }
}

Describe 'v2 output configuration preflight' {
  It 'returns a terminal V2 FAIL before execution when <OutputFormat> lacks OutputPath' -TestCases @(
    @{ OutputFormat = 'Json' }
    @{ OutputFormat = 'Csv' }
  ) {
    param($OutputFormat)

    $path = Join-Path $PSScriptRoot '../../scripts/47-WDAG-Readiness-Audit.ps1'
    $output = @(& $path -OutputFormat $OutputFormat -PassThru -Quiet -NoColor 2>&1 3>&1 6>&1)
    $results = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' })

    $LASTEXITCODE | Should -Be 1
    $results | Should -HaveCount 1
    $results[0].Result | Should -Be 'FAIL'
    @($results[0].Findings | Where-Object Code -eq 'V2-OutputConfigurationInvalid').Count | Should -Be 1
  }
}

Describe '00 control-plane v2 surface' {
  $controlPlaneCases = @(
    Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../../scripts') -Filter '00-*.ps1' -File |
      Sort-Object Name |
      ForEach-Object { [pscustomobject]@{ Name = $_.Name; Path = $_.FullName } }
  )

  It '<_.Name> can construct a V2 result for its own terminal paths' -ForEach $controlPlaneCases {
    $content = Get-Content -LiteralPath $_.Path -Raw -Encoding UTF8

    $content | Should -Match 'Serialization\.psm1'
    $content | Should -Match 'Get-V2ResultObject'
  }
}

Describe 'unsupported-host v2 result contract' {
  $unsupportedHostCases = @(
    Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../../scripts') -Filter '*.ps1' -File |
      Where-Object {
        (Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8) -match 'UnsupportedHost\s*=\s*\$true'
      } |
      Sort-Object Name |
      ForEach-Object {
        [pscustomobject]@{
          Name = $_.Name
          Path = $_.FullName
        }
      }
  )

  It '<_.Name> reports unsupported host as WARN, not success' -ForEach $unsupportedHostCases {
    $case = $_
    if ($env:OS -eq 'Windows_NT') {
      Set-ItResult -Skipped -Because 'Unsupported-host branch requires a non-Windows host.'
      return
    }

    $result = & $case.Path -OutputFormat None -PassThru -Strict:$false -Quiet -NoColor
    $exitCode = $LASTEXITCODE

    $exitCode | Should -Be 2
    $result.Result | Should -Be 'WARN'
    $result.Summary.Supported | Should -BeFalse
    $result.Metadata.UnsupportedHost | Should -BeTrue
  }

  It '<_.Name> promotes unsupported host to FAIL when Strict is requested' -ForEach $unsupportedHostCases {
    $case = $_
    if ($env:OS -eq 'Windows_NT') {
      Set-ItResult -Skipped -Because 'Unsupported-host branch requires a non-Windows host.'
      return
    }

    $result = & $case.Path -OutputFormat None -PassThru -Strict:$true -Quiet -NoColor
    $exitCode = $LASTEXITCODE

    $exitCode | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.Supported | Should -BeFalse
    $result.Metadata.UnsupportedHost | Should -BeTrue
  }

  It '<_.Name> keeps its unsupported-host branch tied to Strict and Get-V2ExitCode' -ForEach $unsupportedHostCases {
    $content = Get-Content -LiteralPath $_.Path -Raw -Encoding UTF8

    $content | Should -Match '\$(?:unsupportedResult|resultToken)\s*=\s*if\s*\(\$Strict\)\s*\{\s*''FAIL''\s*\}\s*else\s*\{\s*''WARN''\s*\}'
    $content | Should -Match 'exit\s*\(\s*Get-V2ExitCode\s+-Result\s+\$(?:unsupportedResult|resultToken)\s*\)'
  }
}

Describe '43 App Control disabled-config v2 contract' {
  It 'returns initialized disabled-config findings and a strict FAIL at runtime' {
    $path = Join-Path $PSScriptRoot '../../scripts/43-AppControlForBusiness-Audit.ps1'
    $configPath = Join-Path $TestDrive 'disabled.json'
    [System.IO.File]::WriteAllText($configPath, ([pscustomobject]@{ Enabled = $false } | ConvertTo-Json), [System.Text.UTF8Encoding]::new($false))

    $originalOs = $env:OS
    try {
      if ($env:OS -ne 'Windows_NT') { $env:OS = 'Windows_NT' }
      $output = @(& $path -ConfigPath $configPath -OutputFormat None -PassThru -Strict -Quiet -NoColor)
      $exitCode = $LASTEXITCODE
    } finally {
      $env:OS = $originalOs
    }

    $result = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' }) | Select-Object -First 1
    $exitCode | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    @($result.Findings | Where-Object Code -eq 'AC-DisabledByConfig').Count | Should -Be 1
  }

  It 'uses initialized findings and promotes its disabled-config result under Strict' {
    $path = Join-Path $PSScriptRoot '../../scripts/43-AppControlForBusiness-Audit.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$disabledFindings\s*=\s*@\(\$script:Findings\.ToArray\(\)\)'
    $content | Should -Match '\$disabledResultToken\s*=\s*if\s*\(\$strictModeEnabled\s+-and\s+\$disabledFindings\.Count\s+-gt\s+0\)\s*\{\s*''FAIL''\s*\}'
    $content | Should -Match '-Findings\s+\$disabledFindings'
    $content | Should -Match 'exit\s*\(\s*Get-V2ExitCode\s+-Result\s+\$disabledResultToken\s*\)'
    $content | Should -Not -Match '-Findings\s+\$findingsArr\s*`?\s*\r?\n\s*-Summary\s+\$summary\s*`?\s*\r?\n\s*-Metadata\s+@\{ Indicators = \$emptyIndicators'
  }
}

Describe 'numbered script v2 process-exit contract' {
  $v2ExitCases = @(
    Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../../scripts') -Filter '*.ps1' -File |
      Where-Object { $_.Name -match '^(?:0[1-9]|[1-4][0-9]|5[0-2])-' } |
      Sort-Object Name |
      ForEach-Object {
        [pscustomobject]@{
          Name = $_.Name
          Path = $_.FullName
        }
      }
  )

  It '<_.Name> maps its final v2 result token to the standard exit code' -ForEach $v2ExitCases {
    $case = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($case.Path, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty

    $topLevelExits = @(
      $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true) |
        Where-Object {
          $insideFunction = $false
          $parent = $_.Parent
          while ($parent) {
            if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
              $insideFunction = $true
              break
            }
            $parent = $parent.Parent
          }
          -not $insideFunction
        } |
        Sort-Object { $_.Extent.StartOffset }
    )

    $topLevelExits | Should -Not -BeNullOrEmpty
    $topLevelExits[-1].Extent.Text | Should -Match '^exit\s*\(\s*Get-V2ExitCode\s+-Result\s+\$resultToken\s*\)$'
  }

  It '<_.Name> does not bypass v2 output on an early top-level exit' -ForEach $v2ExitCases {
    $case = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($case.Path, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty

    $topLevelExits = @(
      $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true) |
        Where-Object {
          $insideFunction = $false
          $parent = $_.Parent
          while ($parent) {
            if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
              $insideFunction = $true
              break
            }
            $parent = $parent.Parent
          }
          -not $insideFunction
        } |
        Sort-Object { $_.Extent.StartOffset }
    )

    $earlyExits = if ($topLevelExits.Count -gt 1) {
      @($topLevelExits[0..($topLevelExits.Count - 2)])
    } else {
      @()
    }

    foreach ($earlyExit in $earlyExits) {
      $containingBlock = $earlyExit.Parent
      while ($containingBlock -and $containingBlock -isnot [System.Management.Automation.Language.StatementBlockAst]) {
        $containingBlock = $containingBlock.Parent
      }

      $containingBlock | Should -Not -BeNullOrEmpty
      $containingBlock.Extent.Text | Should -Match 'Get-V2ResultObject'

      $resultMatch = [regex]::Match($containingBlock.Extent.Text, "-Result\s+'(OK|WARN|FAIL)'")
      $exitMatch = [regex]::Match($earlyExit.Extent.Text, '^exit\s+([012])$')
      if ($resultMatch.Success -and $exitMatch.Success) {
        $expectedExit = switch ($resultMatch.Groups[1].Value) {
          'OK' { 0 }
          'WARN' { 2 }
          'FAIL' { 1 }
        }
        [int]$exitMatch.Groups[1].Value | Should -Be $expectedExit
      }
    }
  }

  It '<_.Name> does not bypass terminal v2 output with a top-level return' -ForEach $v2ExitCases {
    $case = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($case.Path, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty

    $topLevelReturns = @(
      $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ReturnStatementAst] }, $true) |
        Where-Object {
          $insideNestedCode = $false
          $parent = $_.Parent
          while ($parent) {
            if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst] -or
                $parent -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
              $insideNestedCode = $true
              break
            }
            $parent = $parent.Parent
          }
          -not $insideNestedCode
        }
    )

    $topLevelReturns | Should -BeNullOrEmpty
  }
}
