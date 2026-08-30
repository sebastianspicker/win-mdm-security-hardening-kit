<#
.SYNOPSIS
Serialization and v2 result object utilities.

.DESCRIPTION
Provides functions to save objects as JSON or CSV, create standardized v2 result
objects, and write result objects in the configured output format.
#>

Set-StrictMode -Version Latest
Microsoft.PowerShell.Core\Import-Module ([System.IO.Path]::Combine($PSScriptRoot, 'Validation.psm1'))

<#
.SYNOPSIS
  Converts scalar or collection input to an object array.
.DESCRIPTION
  Normalizes serialization inputs while preserving null and enumerable values.
#>
function ConvertTo-ObjectArray {
  [CmdletBinding()]
  param([AllowNull()][object]$InputObject)

  if ($null -eq $InputObject) { return ,@() }

  if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($item in $InputObject) {
      $items.Add($item) | Out-Null
    }
    return ,$items.ToArray()
  }

  return ,@($InputObject)
}

<#
.SYNOPSIS
  Serializes an object to a JSON file.
.PARAMETER InputObject
  Object to serialize.
.PARAMETER Path
  Output file path. Parent directory is created if needed.
.PARAMETER Depth
  JSON serialization depth (default 20).
.PARAMETER NoBom
  Retained for compatibility. JSON is always UTF-8 without a byte-order mark.
#>
function Save-Json {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [object]$InputObject,
    [Parameter(Mandatory)]
    [string]$Path,
    [int]$Depth = 20,
    [switch]$NoBom
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw 'Save-Json: Path cannot be null or empty.'
  }
  if (Validation\Test-PathTraversal -Path $Path) {
    throw 'Save-Json: Path must not contain path traversal segments ("..").'
  }
  if (-not (Validation\Initialize-SafeOutputFilePath -Path $Path)) {
    throw 'Save-Json: Path must reference a local file without traversal, UNC/device, or reparse-point components.'
  }

  $json = $InputObject | ConvertTo-Json -Depth $Depth
  $null = $NoBom
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
}

function ConvertTo-CsvSafeCellValue {
  [CmdletBinding()]
  param([AllowNull()][object]$Value)

  if ($Value -is [string] -and $Value -match '^[\s\x00-\x1F]*[=+\-@]') {
    return "'$Value"
  }
  return $Value
}

function ConvertTo-CsvSafeObject {
  [CmdletBinding()]
  param([AllowNull()][object]$InputObject)

  if ($null -eq $InputObject) {
    return $null
  }

  $safeProperties = [ordered]@{}
  foreach ($property in $InputObject.PSObject.Properties) {
    $safeProperties[$property.Name] = ConvertTo-CsvSafeCellValue -Value $property.Value
  }
  return [pscustomobject]$safeProperties
}

<#
.SYNOPSIS
  Exports objects to a CSV file.
.PARAMETER InputObject
  Objects to export.
.PARAMETER Path
  Output CSV file path. Parent directory is created if needed.
#>
function Save-Csv {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [object[]]$InputObject,
    [Parameter(Mandatory)]
    [string]$Path
  )

  if (Validation\Test-PathTraversal -Path $Path) {
    throw 'Save-Csv: Path must not contain path traversal segments ("..").'
  }
  if (-not (Validation\Initialize-SafeOutputFilePath -Path $Path)) {
    throw 'Save-Csv: Path must reference a local file without traversal, UNC/device, or reparse-point components.'
  }

  $safeInput = foreach ($item in $InputObject) {
    ConvertTo-CsvSafeObject -InputObject $item
  }
  $lines = @($safeInput | ConvertTo-Csv -NoTypeInformation)
  $csv = if ($lines.Count -gt 0) { ($lines -join "`r`n") + "`r`n" } else { '' }
  $utf8Bom = New-Object System.Text.UTF8Encoding($true)
  [System.IO.File]::WriteAllText($Path, $csv, $utf8Bom)
}

<#
.SYNOPSIS
  Creates a standardized v2 result object.
.PARAMETER ScriptName
  Name of the calling script (e.g. '27-Defender-Health-Audit.ps1').
.PARAMETER Mode
  Execution mode: Audit or Remediate.
.PARAMETER Result
  Overall result: OK, WARN, or FAIL.
.PARAMETER Findings
  Array of finding objects to include.
.PARAMETER Summary
  Optional summary object with script-specific details.
.PARAMETER Metadata
  Optional hashtable of additional metadata.
.PARAMETER SchemaVersion
  Schema version string (default '2.0').
#>
function Get-V2ResultObject {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$ScriptName,
    [Parameter(Mandatory)]
    [ValidateSet('Audit','Remediate')]
    [string]$Mode,
    [Parameter(Mandatory)]
    [ValidateSet('OK','WARN','FAIL')]
    [string]$Result,
    [AllowNull()]
    [object]$Findings = @(),
    [object]$Summary = $null,
    [hashtable]$Metadata = @{},
    [string]$SchemaVersion = '2.0'
  )

  $findingArray = @()
  if ($null -ne $Findings) {
    if ($Findings -is [System.Collections.IEnumerable] -and $Findings -isnot [string]) {
      $tmp = New-Object System.Collections.Generic.List[object]
      foreach ($finding in $Findings) {
        $tmp.Add($finding) | Out-Null
      }
      $findingArray = $tmp.ToArray()
    } else {
      $findingArray = @($Findings)
    }
  }

  return [pscustomobject]@{
    SchemaVersion = $SchemaVersion
    ScriptName    = $ScriptName
    Mode          = $Mode
    ComputerName  = $env:COMPUTERNAME
    TimestampUtc  = (Get-Date).ToUniversalTime()
    Result        = $Result
    Findings      = $findingArray
    Summary       = $Summary
    Metadata      = $Metadata
  }
}

<#
.SYNOPSIS
  Maps a v2 result token to its process exit code.
.PARAMETER Result
  Overall result token: OK, WARN, or FAIL.
#>
function Get-V2ExitCode {
  [CmdletBinding()]
  [OutputType([int])]
  param(
    [Parameter(Mandatory)]
    [ValidateSet('OK','WARN','FAIL')]
    [string]$Result
  )

  switch ($Result) {
    'OK'   { return 0 }
    'WARN' { return 2 }
    'FAIL' { return 1 }
  }
}

<#
.SYNOPSIS
  Returns a validation error for an invalid v2 output configuration.
.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.
.PARAMETER OutputPath
  File path required for Json and Csv formats.
#>
function Get-V2OutputConfigurationError {
  [CmdletBinding()]
  [OutputType([string])]
  param(
    [ValidateSet('Console','Json','Csv','None')]
    [string]$OutputFormat = 'Console',
    [AllowNull()]
    [string]$OutputPath
  )

  if ($OutputFormat -notin @('Json', 'Csv')) {
    return $null
  }
  if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    return "OutputPath is required when OutputFormat is $OutputFormat."
  }
  if (Validation\Test-PathTraversal -Path $OutputPath) {
    return 'OutputPath must not contain path traversal segments ("..").'
  }
  if (Test-Path -LiteralPath $OutputPath -PathType Container) {
    return 'OutputPath must reference a file, not a directory.'
  }
  if (-not (Validation\Test-SafeOutputFilePath -Path $OutputPath)) {
    return 'OutputPath must reference a local file without traversal, UNC/device, or reparse-point components.'
  }

  return $null
}

<#
.SYNOPSIS
  Writes a result object in the specified output format.
.PARAMETER ResultObject
  The v2 result object to output.
.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.
.PARAMETER OutputPath
  File path required for Json and Csv formats.
#>
function Write-ResultObject {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [object]$ResultObject,
    [ValidateSet('Console','Json','Csv','None')]
    [string]$OutputFormat = 'Console',
    [string]$OutputPath
  )

  $configurationError = Get-V2OutputConfigurationError -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($configurationError) {
    throw $configurationError
  }

  switch ($OutputFormat) {
    'None' {
      return
    }
    'Console' {
      return
    }
    'Json' {
      Save-Json -InputObject $ResultObject -Path $OutputPath -Depth 10 -NoBom
      return
    }
    'Csv' {
      if ($ResultObject.PSObject.Properties.Name -contains 'Findings') {
        Save-Csv -InputObject @($ResultObject.Findings) -Path $OutputPath
      } else {
        Save-Csv -InputObject @($ResultObject) -Path $OutputPath
      }
      return
    }
  }
}

<#
.SYNOPSIS
  Returns a v2 result object as a formatted JSON string suitable for machine consumption.
.DESCRIPTION
  Wraps ConvertTo-Json with consistent depth and encoding settings. The output
  uses depth 10 by default, which is sufficient for nested finding objects with
  Extra properties while avoiding circular reference issues.
.PARAMETER ResultObject
  The v2 result object to serialize.
.PARAMETER Depth
  JSON serialization depth (default 10).
#>
function ConvertTo-V2Json {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [object]$ResultObject,
    [int]$Depth = 10
  )

  return ($ResultObject | ConvertTo-Json -Depth $Depth)
}

Export-ModuleMember -Function `
  ConvertTo-ObjectArray, `
  Save-Json, `
  Save-Csv, `
  Get-V2ResultObject, `
  Get-V2ExitCode, `
  Get-V2OutputConfigurationError, `
  Write-ResultObject, `
  ConvertTo-V2Json
