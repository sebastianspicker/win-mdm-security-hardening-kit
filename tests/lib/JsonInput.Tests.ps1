#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for bounded shared JSON input and its public adapters.
.DESCRIPTION
Verifies the low-level size and parse contract without merging the distinct
Config and JsonCatalog adapter semantics.
#>

BeforeAll {
  $script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  Import-Module (Join-Path $PSScriptRoot '../../lib/JsonInput.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../../lib/Config.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../../lib/JsonCatalog.psm1') -Force
}

Describe 'Read-BoundedUtf8JsonInput' {
  It 'parses bounded UTF-8 JSON while preserving the source text' {
    $path = Join-Path $TestDrive 'input.json'
    [System.IO.File]::WriteAllText($path, '{"Name":"catalog"}', $script:Utf8NoBom)

    $input = Read-BoundedUtf8JsonInput -Path $path -MaximumBytes 64

    $input.Text | Should -Be '{"Name":"catalog"}'
    $input.Data.Name | Should -Be 'catalog'
  }

  It 'rejects JSON input over the configured byte limit' {
    $path = Join-Path $TestDrive 'oversized.json'
    [System.IO.File]::WriteAllText($path, '{"Name":"catalog"}', $script:Utf8NoBom)

    { Read-BoundedUtf8JsonInput -Path $path -MaximumBytes 8 } |
      Should -Throw '*8 byte size limit*'
  }

  It 'returns invalid JSON to the adapter that owns its error policy' {
    $path = Join-Path $TestDrive 'invalid.json'
    [System.IO.File]::WriteAllText($path, '{"Name":', $script:Utf8NoBom)

    $input = Read-BoundedUtf8JsonInput -Path $path

    $input.Data | Should -BeNullOrEmpty
    $input.ParseError | Should -Not -BeNullOrEmpty
  }
}

Describe 'JSON input adapters' {
  It 'keeps Config default merge and parse-fallback metadata semantics' {
    $validPath = Join-Path $TestDrive 'config-valid.json'
    $invalidPath = Join-Path $TestDrive 'config-invalid.json'
    [System.IO.File]::WriteAllText($validPath, '{"Enabled":false,"Ignored":"value"}', $script:Utf8NoBom)
    [System.IO.File]::WriteAllText($invalidPath, '{"Enabled":', $script:Utf8NoBom)

    $loaded = Read-ConfigWithDefaults -Path $validPath -Defaults @{ Enabled = $true; Count = 2 }
    $fallback = Read-ConfigWithDefaults -Path $invalidPath -Defaults @{ Enabled = $true; Count = 2 }

    $loaded.Config.Enabled | Should -BeFalse
    $loaded.Config.Count | Should -Be 2
    $loaded.Config.PSObject.Properties.Name | Should -Not -Contain 'Ignored'
    $loaded.Meta.Loaded | Should -BeTrue
    $loaded.Meta.UsedDefaults | Should -BeFalse
    $fallback.Config.Enabled | Should -BeTrue
    $fallback.Meta.Loaded | Should -BeFalse
    $fallback.Meta.UsedDefaults | Should -BeTrue
    $fallback.Meta.UsedDefaultsBecause | Should -Be 'Config parse failed.'
    $fallback.Meta.Error | Should -Not -BeNullOrEmpty
  }

  It 'keeps JsonCatalog loaded and invalid status-envelope semantics' {
    $validPath = Join-Path $TestDrive 'catalog-valid.json'
    $invalidPath = Join-Path $TestDrive 'catalog-invalid.json'
    [System.IO.File]::WriteAllText($validPath, '{"Name":"catalog"}', $script:Utf8NoBom)
    [System.IO.File]::WriteAllText($invalidPath, '{"Name":', $script:Utf8NoBom)

    $loaded = Read-JsonFileWithStatus -Path $validPath
    $invalid = Read-JsonFileWithStatus -Path $invalidPath

    $loaded.Data.Name | Should -Be 'catalog'
    $loaded.Meta.Loaded | Should -BeTrue
    $loaded.Meta.Status | Should -Be 'Loaded'
    $invalid.Data | Should -BeNullOrEmpty
    $invalid.Meta.Loaded | Should -BeFalse
    $invalid.Meta.Status | Should -Be 'Invalid'
    $invalid.Meta.Error | Should -Not -BeNullOrEmpty
  }
}
