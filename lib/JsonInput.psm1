#requires -version 5.1
<#
.SYNOPSIS
Bounded UTF-8 JSON input primitive.

.DESCRIPTION
Reads a UTF-8 file through Validation's stable bounded-file handle and parses
non-empty JSON. Callers own path policy and their public error semantics.
#>

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Validation.psm1')

<#
.SYNOPSIS
  Reads bounded UTF-8 JSON input.
.DESCRIPTION
  Returns the source text, parsed value, and any parse error. Empty input is
  deliberately returned without a parsed value so adapters can retain their own
  empty-input contracts. File-read failures propagate; adapters decide how to
  represent a parse error.
#>
function Read-BoundedUtf8JsonInput {
  [CmdletBinding()]
  [OutputType([pscustomobject])]
  param(
    [Parameter(Mandatory)][string]$Path,
    [ValidateRange(1, 16777216)][int64]$MaximumBytes = 1048576
  )

  $text = Validation\Get-BoundedUtf8FileContent -Path $Path -MaximumBytes $MaximumBytes
  $data = $null
  $parseError = $null
  if (-not [string]::IsNullOrWhiteSpace($text)) {
    try {
      $data = $text | ConvertFrom-Json -ErrorAction Stop
    } catch {
      $parseError = $_.Exception
    }
  }

  return [pscustomobject]@{ Text = $text; Data = $data; ParseError = $parseError }
}

Export-ModuleMember -Function Read-BoundedUtf8JsonInput
