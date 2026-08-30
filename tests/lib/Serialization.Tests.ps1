#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for library-module contracts.

.DESCRIPTION
Verifies module behavior that security automation depends on.
#>

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Serialization.psm1') -Force
}

Describe 'Get-V2ResultObject' {
  It 'Creates required contract fields' {
    $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'OK' -Findings @() -Summary @{ A = 1 } -Metadata @{}
    $obj.SchemaVersion | Should -Be '2.0'
    $obj.ScriptName | Should -Be 'x.ps1'
    $obj.Mode | Should -Be 'Audit'
    $obj.Result | Should -Be 'OK'
  }

  It 'Includes ComputerName and TimestampUtc' {
    $obj = Get-V2ResultObject -ScriptName 'y.ps1' -Mode 'Remediate' -Result 'WARN' -Findings @() -Summary @{} -Metadata @{}
    $obj.PSObject.Properties.Name | Should -Contain 'ComputerName'
    $obj.PSObject.Properties.Name | Should -Contain 'TimestampUtc'
  }

  It 'Stores Findings as array' {
    $findings = @([pscustomobject]@{ Code = 'A'; Severity = 'High' })
    $obj = Get-V2ResultObject -ScriptName 'z.ps1' -Mode 'Audit' -Result 'FAIL' -Findings $findings -Summary @{} -Metadata @{}
    @($obj.Findings).Count | Should -Be 1
    $obj.Findings[0].Code | Should -Be 'A'
  }

  It 'Rejects invalid Mode via ValidateSet' {
    { Get-V2ResultObject -ScriptName 'z.ps1' -Mode 'Invalid' -Result 'OK' -Findings @() -Summary @{} -Metadata @{} } | Should -Throw
  }

  It 'Rejects invalid Result via ValidateSet' {
    { Get-V2ResultObject -ScriptName 'z.ps1' -Mode 'Audit' -Result 'INVALID' -Findings @() -Summary @{} -Metadata @{} } | Should -Throw
  }
}

Describe 'Get-V2ExitCode' {
  It 'Maps <Result> to exit code <ExitCode>' -ForEach @(
    @{ Result = 'OK'; ExitCode = 0 }
    @{ Result = 'WARN'; ExitCode = 2 }
    @{ Result = 'FAIL'; ExitCode = 1 }
  ) {
    Get-V2ExitCode -Result $Result | Should -Be $ExitCode
  }

  It 'Rejects an unknown result token' {
    { Get-V2ExitCode -Result 'UNKNOWN' } | Should -Throw
  }
}

Describe 'Get-V2OutputConfigurationError' {
  It 'accepts non-file formats without an output path' -ForEach @('Console', 'None') {
    Get-V2OutputConfigurationError -OutputFormat $_ | Should -BeNullOrEmpty
  }

  It 'requires an output path for <_>' -ForEach @('Json', 'Csv') {
    Get-V2OutputConfigurationError -OutputFormat $_ | Should -Be "OutputPath is required when OutputFormat is $_."
  }

  It 'rejects traversal before serialization' {
    Get-V2OutputConfigurationError -OutputFormat Json -OutputPath '../escape.json' |
      Should -BeLike '*path traversal*'
  }

  It 'rejects a directory as a file output path' {
    Get-V2OutputConfigurationError -OutputFormat Json -OutputPath ([System.IO.Path]::GetTempPath()) |
      Should -BeLike '*not a directory*'
  }
}

Describe 'Save-Json' {
  It 'Writes JSON file' {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      Save-Json -InputObject @{ test = 1 } -Path $tmp -NoBom
      Test-Path -LiteralPath $tmp | Should -Be $true
      $raw = Get-Content -LiteralPath $tmp -Raw
      $raw | Should -Match '"test"'
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Allows double dots inside JSON file name segment' {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-name..dots-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      Save-Json -InputObject @{ test = 1 } -Path $tmp -NoBom
      Test-Path -LiteralPath $tmp | Should -Be $true
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Auto-creates parent directory' {
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-dir-{0}" -f [guid]::NewGuid().ToString('N'))
    $tmp = Join-Path $tmpDir 'output.json'
    try {
      Save-Json -InputObject @{ auto = 'dir' } -Path $tmp -NoBom
      Test-Path -LiteralPath $tmp | Should -Be $true
    } finally {
      if (Test-Path -LiteralPath $tmpDir) { Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Writes without BOM when NoBom switch is set' {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-nobom-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      Save-Json -InputObject @{ bom = 'test' } -Path $tmp -NoBom
      $bytes = [System.IO.File]::ReadAllBytes($tmp)
      # BOM for UTF-8 is 0xEF 0xBB 0xBF; verify it is NOT present
      if ($bytes.Length -ge 3) {
        ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -Be $false
      }
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Writes without BOM by default on every supported runtime' {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-default-nobom-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      Save-Json -InputObject @{ bom = 'test' } -Path $tmp
      $bytes = [System.IO.File]::ReadAllBytes($tmp)
      ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) |
        Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Throws for empty path' {
    { Save-Json -InputObject @{ A = 1 } -Path '' } | Should -Throw '*Path*'
  }

  It 'Throws for path traversal attempt' {
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) 'ser-traversal-test'
    { Save-Json -InputObject @{ A = 1 } -Path (Join-Path $tmpDir '../../escape.json') } | Should -Throw '*path traversal*'
  }

  It 'Roundtrip: write then read returns same data' {
    Import-Module (Join-Path $PSScriptRoot '../../lib/JsonCatalog.psm1') -Force
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-rt-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      $original = [pscustomobject]@{ Name = 'Roundtrip'; Items = @(1, 2, 3) }
      Save-Json -InputObject $original -Path $tmp -NoBom
      $loaded = Read-JsonFileSafe -Path $tmp
      $loaded.Name | Should -Be 'Roundtrip'
      $loaded.Items.Count | Should -Be 3
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
  }
}

Describe 'Save-Csv' {
  It 'Writes CSV file with header row' {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-csv-{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
      $data = @(
        [pscustomobject]@{ Name = 'Alice'; Score = 95 }
        [pscustomobject]@{ Name = 'Bob'; Score = 87 }
      )
      Save-Csv -InputObject $data -Path $tmp
      Test-Path -LiteralPath $tmp | Should -Be $true
      $lines = Get-Content -LiteralPath $tmp
      # First line should be header
      $lines[0] | Should -Match 'Name'
      $lines[0] | Should -Match 'Score'
      # Should have header + 2 data rows
      $lines.Count | Should -BeGreaterOrEqual 3
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Writes an explicit UTF-8 BOM for operator-facing CSV output' {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-bom-{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
      Save-Csv -InputObject @([pscustomobject]@{ Name = 'Alice' }) -Path $tmp
      $bytes = [System.IO.File]::ReadAllBytes($tmp)
      $bytes[0] | Should -Be 0xEF
      $bytes[1] | Should -Be 0xBB
      $bytes[2] | Should -Be 0xBF
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Allows double dots inside CSV file name segment' {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-csv-name..dots-{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
      Save-Csv -InputObject @([pscustomobject]@{ Name = 'Alice' }) -Path $tmp
      Test-Path -LiteralPath $tmp | Should -Be $true
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Handles special characters in values' {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-csv-special-{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
      $data = @(
        [pscustomobject]@{ Name = 'O''Brien'; Message = 'Hello, "World"' }
      )
      Save-Csv -InputObject $data -Path $tmp
      Test-Path -LiteralPath $tmp | Should -Be $true
      $content = Get-Content -LiteralPath $tmp -Raw
      $content | Should -Match 'Brien'
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'neutralizes spreadsheet formulas after leading whitespace or control characters' {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-csv-formula-{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
      $controlPrefix = ([char]1) + '=HYPERLINK("https://example.test")'
      Save-Csv -InputObject @(
        [pscustomobject]@{ Value = '=1+1' },
        [pscustomobject]@{ Value = ' +SUM(A1:A2)' },
        [pscustomobject]@{ Value = $controlPrefix }
      ) -Path $tmp

      $values = @(Import-Csv -LiteralPath $tmp | ForEach-Object Value)
      $values | Should -Be @("'=1+1", "' +SUM(A1:A2)", ("'" + $controlPrefix))
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'keeps JSON values lossless' {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-json-lossless-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      Save-Json -InputObject ([pscustomobject]@{ Value = '=1+1' }) -Path $tmp
      (Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json).Value | Should -Be '=1+1'
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Auto-creates parent directory for CSV' {
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-csvdir-{0}" -f [guid]::NewGuid().ToString('N'))
    $tmp = Join-Path $tmpDir 'output.csv'
    try {
      Save-Csv -InputObject @([pscustomobject]@{ A = 1 }) -Path $tmp
      Test-Path -LiteralPath $tmp | Should -Be $true
    } finally {
      if (Test-Path -LiteralPath $tmpDir) { Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
  }
}

Describe 'Write-ResultObject' {
  It 'Throws for Json without OutputPath' {
    $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'OK' -Findings @() -Summary @{} -Metadata @{}
    { Write-ResultObject -ResultObject $obj -OutputFormat Json } | Should -Throw
  }

  It 'Throws for Csv without OutputPath' {
    $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'OK' -Findings @() -Summary @{} -Metadata @{}
    { Write-ResultObject -ResultObject $obj -OutputFormat Csv } | Should -Throw
  }

  It 'Does not throw for None format' {
    $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'OK' -Findings @() -Summary @{} -Metadata @{}
    { Write-ResultObject -ResultObject $obj -OutputFormat None } | Should -Not -Throw
  }

  It 'Does not throw for Console format' {
    $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'OK' -Findings @() -Summary @{} -Metadata @{}
    { Write-ResultObject -ResultObject $obj -OutputFormat Console } | Should -Not -Throw
  }

  It 'Treats Console and None formats as intentional no-ops' {
    $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'OK' -Findings @() -Summary @{} -Metadata @{}

    @(Write-ResultObject -ResultObject $obj -OutputFormat Console 6>&1) | Should -HaveCount 0
    @(Write-ResultObject -ResultObject $obj -OutputFormat None 6>&1) | Should -HaveCount 0
  }

  It 'Writes JSON file when OutputPath is provided' {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("wr-json-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'OK' -Findings @() -Summary @{} -Metadata @{}
      Write-ResultObject -ResultObject $obj -OutputFormat Json -OutputPath $tmp
      Test-Path -LiteralPath $tmp | Should -Be $true
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Writes CSV file when OutputPath is provided' {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("wr-csv-{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
      $findings = @([pscustomobject]@{ Code = 'T1'; Severity = 'High'; Message = 'fail' })
      $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'FAIL' -Findings $findings -Summary @{} -Metadata @{}
      Write-ResultObject -ResultObject $obj -OutputFormat Csv -OutputPath $tmp
      Test-Path -LiteralPath $tmp | Should -Be $true
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
  }
}
