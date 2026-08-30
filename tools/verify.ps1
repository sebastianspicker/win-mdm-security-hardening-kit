#requires -version 5.1

<#
.SYNOPSIS
  Runs repository static verification gates.
.DESCRIPTION
  Checks public files and configured analyzers to catch release-blocking regressions.
#>

[CmdletBinding()]
param(
  [string]$RootPath = '',
  [switch]$SkipAnalyzer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RootPath)) {
  $scriptPath = $MyInvocation.MyCommand.Path
  if (-not $scriptPath) { $scriptPath = $PSCommandPath }
  if (-not $scriptPath) { $scriptPath = (Get-Location).Path }

  if (Test-Path -LiteralPath $scriptPath -PathType Container) {
    $scriptDir = $scriptPath
  } else {
    $scriptDir = Split-Path -Parent $scriptPath
  }

  $RootPath = (Resolve-Path (Join-Path $scriptDir '..')).Path
}
$RootPath = (Resolve-Path -LiteralPath $RootPath -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $RootPath -PathType Container)) {
  throw "Verification root is not a directory: $RootPath"
}

$bootstrapPath = [System.IO.Path]::Combine($RootPath, 'scripts', '_lib', 'Bootstrap.ps1')
if (-not (Test-Path -LiteralPath $bootstrapPath)) {
  Write-Error "Bootstrap not found: $bootstrapPath"
  exit 1
}
. $bootstrapPath
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../lib/External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot '../lib/Validation.psm1')

Write-Section -Title 'verify.ps1 - Static Checks'

$script:GateResults = New-Object System.Collections.Generic.List[object]

<#
.SYNOPSIS
  Records one verification gate outcome.
.DESCRIPTION
  Adds a named status and detail record to the final verification report.
#>
function Add-GateResult {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('PASS','FAILED','SKIPPED')][string]$Status,
    [string]$Detail = ''
  )

  [void]$script:GateResults.Add([pscustomobject]@{
      Name   = $Name
      Status = $Status
      Detail = $Detail
    })
}

<#
.SYNOPSIS
  Prints the final verification verdict and exits.
.DESCRIPTION
  Reports each gate result before returning the selected process exit code.
#>
function Complete-Verification {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('PASS','FAILED','PARTIAL')][string]$Verdict,
    [Parameter(Mandatory)][int]$ExitCode
  )

  Write-Section -Title 'Verification Gate Summary'
  foreach ($gate in $script:GateResults) {
    Write-UiLine ("{0,-12} {1,-8} {2}" -f $gate.Name, $gate.Status, $gate.Detail)
  }

  switch ($Verdict) {
    'PASS' { Write-Success -Message 'VERDICT: PASS' }
    'PARTIAL' { Write-Warn -Message 'VERDICT: PARTIAL' }
    'FAILED' { Write-ErrorLine -Message 'VERDICT: FAILED' }
  }

  exit $ExitCode
}

<#
.SYNOPSIS
  Gets paths that belong to the repository public surface.
.DESCRIPTION
  Recursively enumerates files while excluding local-only and generated areas.
#>
function Get-PublicSurfacePaths {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (Test-CommandExists -Name 'git') {
    $gitRootResult = Invoke-NativeCommand -Command 'git' -Arguments @('-C', $Path, 'rev-parse', '--is-inside-work-tree') `
      -CaptureOutput -Quiet -TimeoutSeconds 30 -MaxOutputBytes 1048576
    $gitResultComplete = $gitRootResult -and $gitRootResult.Success -and -not $gitRootResult.TimedOut -and
      -not $gitRootResult.OutputTruncated -and -not $gitRootResult.StderrTruncated
    if ($gitResultComplete -and $gitRootResult.Stdout.Trim() -eq 'true') {
      $gitFilesResult = Invoke-NativeCommand -Command 'git' -Arguments @('-C', $Path, 'ls-files', '-z', '--cached', '--others', '--exclude-standard') `
        -CaptureOutput -Quiet -TimeoutSeconds 30 -MaxOutputBytes 1048576
      $gitFilesComplete = $gitFilesResult -and $gitFilesResult.Success -and -not $gitFilesResult.TimedOut -and
        -not $gitFilesResult.OutputTruncated -and -not $gitFilesResult.StderrTruncated
      if ($gitFilesComplete) {
        $rootFull = [System.IO.Path]::GetFullPath($Path).TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
        $verifiedPaths = New-Object System.Collections.Generic.List[string]
        foreach ($relativePath in $gitFilesResult.Stdout.Split([char]0, [System.StringSplitOptions]::RemoveEmptyEntries)) {
          if ([System.IO.Path]::IsPathRooted($relativePath) -or $relativePath -match '[\x00-\x1F\x7F]') {
            throw 'git returned an unsafe repository-relative path.'
          }
          $candidate = [System.IO.Path]::GetFullPath((Join-Path $rootFull $relativePath))
          if (-not (Test-PathUnderRoot -Path $candidate -Root $rootFull)) {
            throw 'git returned a path outside the requested verification root.'
          }
          if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            [void]$verifiedPaths.Add($relativePath)
          }
        }
        return @($verifiedPaths | Sort-Object -Unique)
      }
    }
  }

  return @(
    Get-ChildItem -LiteralPath $Path -File -Recurse -Force |
      Where-Object { $_.FullName -notmatch '[/\\]\.git[/\\]' } |
      ForEach-Object {
        $trimmedRoot = $Path.TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
        $_.FullName.Substring($trimmedRoot.Length).TrimStart([char[]]@([char]'/', [char]92))
      }
  )
}

<#
.SYNOPSIS
  Tests whether a relative path belongs to the public surface.
.DESCRIPTION
  Applies the verifier's explicit exclusions for local and generated content.
#>
function Test-PublicSurfacePath {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$RelativePath)

  $path = $RelativePath.Replace([char]92, [char]47).ToLowerInvariant()
  while ($path.StartsWith('./')) {
    $path = $path.Substring(2)
  }
  $path = $path.TrimStart([char]47)
  $segments = @($path.Split('/', [System.StringSplitOptions]::RemoveEmptyEntries))
  if ($segments.Count -eq 0) { return $null }

  $fileName = $segments[-1]
  $blockedDirectorySegments = @(
    'private', '.agents', '.codex', '.codacy', '.claude', '.continue', '.cursor',
    '.aider', '.serena', '.codegraph', '.windsurf', 'credentials', 'secrets',
    'keys', 'certs', 'certificates'
  )
  if ($segments | Where-Object { $blockedDirectorySegments -contains $_ }) {
    return 'private, agent-state, or credential directory'
  }

  $agentInstructionFiles = @(
    'agents.md', 'agent.md', 'claude.md', 'codex.md', 'gemini.md', 'audit.md',
    'harness_principles.md', 'code_review.md'
  )
  if ($agentInstructionFiles -contains $fileName) {
    return 'agent instruction or workspace-state file'
  }

  if (
    $path -match '^\.github/(agents|codex|instructions|prompts)(/|$)' -or
    $path -eq '.github/copilot-instructions.md' -or
    $path -eq '.github/workflows/codex.yml'
  ) {
    return 'agent instruction or workspace-state file'
  }

  if ($fileName -match '^\.env($|\.)|^\.envrc$|^(id_rsa|id_ed25519)(\.pub)?$|\.(pem|key|pfx|p12|cer|crt|jks|kdbx|ppk)$') {
    return 'environment, credential, key, or certificate file'
  }

  if ($fileName -match '\.local(?:\..*)?$|\.(db|sqlite|sqlite3|keystore)$') {
    return 'local secret, database, or keystore file'
  }

  $documentationExtensions = @('.md', '.txt', '.json', '.jsonl', '.yaml', '.yml')
  $isWorkspaceDocument = (
    $documentationExtensions -contains [System.IO.Path]::GetExtension($fileName) -and
    $fileName -match '(ledger|remediation)'
  )
  if (
    $isWorkspaceDocument -or
    $segments[0] -eq 'archive' -or
    ($segments[0] -eq 'docs' -and $path -match '(^|/)(agent|internal|archive|source-audit|tmp|temp)(/|$)')
  ) {
    return 'local ledger, remediation, or workspace documentation'
  }

  $reviewedPublicDocs = @(
    'docs/readme.md',
    'docs/alpha-release.md',
    'docs/architecture.md',
    'docs/decisions/0001-single-runtime.md',
    'docs/launcher-gui.md',
    'docs/rust-v3.md'
  )
  if ($segments[0] -eq 'docs' -and $path -notin $reviewedPublicDocs) {
    return 'documentation path is not in the reviewed public allowlist'
  }

  return $null
}

if (-not (Test-Path -LiteralPath (Join-Path $RootPath 'scripts'))) {
  Write-ErrorLine -Message "scripts/ folder not found under $RootPath"
  exit 1
}
if (-not (Test-Path -LiteralPath (Join-Path $RootPath 'lib'))) {
  Write-ErrorLine -Message "lib/ folder not found under $RootPath"
  exit 1
}
if (-not (Test-Path -LiteralPath $bootstrapPath)) {
  Write-ErrorLine -Message "scripts/_lib/Bootstrap.ps1 not found under $RootPath"
  exit 1
}

$publicSurfaceViolations = @()
foreach ($relativePath in Get-PublicSurfacePaths -Path $RootPath) {
  $reason = Test-PublicSurfacePath -RelativePath $relativePath
  if ($reason) {
    $publicSurfaceViolations += [pscustomobject]@{ Path = $relativePath; Reason = $reason }
  }
}
if ($publicSurfaceViolations.Count -gt 0) {
  Write-ErrorLine -Message ("Public surface violations: {0}" -f $publicSurfaceViolations.Count)
  $publicSurfaceViolations | Sort-Object Path | ForEach-Object {
    Write-UiLine ("- {0} ({1})" -f $_.Path, $_.Reason) -ForegroundColor Yellow
  }
  Add-GateResult -Name 'PublicSurface' -Status 'FAILED' -Detail ("{0} prohibited public path(s)" -f $publicSurfaceViolations.Count)
  Complete-Verification -Verdict 'FAILED' -ExitCode 1
}
Write-Success -Message 'Public surface checks: OK'
Add-GateResult -Name 'PublicSurface' -Status 'PASS' -Detail 'No prohibited tracked or untracked non-ignored paths'

$targets = @()
$targets += Get-ChildItem -Path (Join-Path $RootPath 'scripts') -Filter '*.ps1' -File -Recurse
$targets += Get-ChildItem -Path (Join-Path $RootPath 'lib') -Filter '*.psm1' -File -Recurse
if (Test-Path -LiteralPath (Join-Path $RootPath 'tools')) {
  $targets += Get-ChildItem -Path (Join-Path $RootPath 'tools') -Filter '*.ps1' -File -Recurse
  $targets += Get-ChildItem -Path (Join-Path $RootPath 'tools') -Filter '*.psm1' -File -Recurse
}

Write-Info -Message ("Parsing {0} PowerShell files..." -f $targets.Count)
$parseErrors = @()

foreach ($t in $targets) {
  $tokens = $null
  $errors = $null
  [System.Management.Automation.Language.Parser]::ParseFile($t.FullName, [ref]$tokens, [ref]$errors) | Out-Null
  if ($errors -and $errors.Count -gt 0) {
    foreach ($e in $errors) {
      $parseErrors += [pscustomobject]@{
        File    = $t.FullName
        Message = $e.Message
        Line    = $e.Extent.StartLineNumber
        Column  = $e.Extent.StartColumnNumber
      }
    }
  }
}

if ($parseErrors.Count -gt 0) {
  Write-ErrorLine -Message ("Parse errors: {0}" -f $parseErrors.Count)
  $parseErrors | Sort-Object File,Line,Column | ForEach-Object {
    Write-UiLine ("- {0}:{1}:{2} {3}" -f $_.File, $_.Line, $_.Column, $_.Message) -ForegroundColor Yellow
  }
  Add-GateResult -Name 'Parse' -Status 'FAILED' -Detail ("{0} file(s), {1} parse error(s)" -f $targets.Count, $parseErrors.Count)
  Complete-Verification -Verdict 'FAILED' -ExitCode 1
}

Write-Success -Message 'Parse checks: OK'
Add-GateResult -Name 'Parse' -Status 'PASS' -Detail ("{0} file(s)" -f $targets.Count)

if ($SkipAnalyzer) {
  Write-Warn -Message 'PSScriptAnalyzer: SKIPPED (-SkipAnalyzer)'
  Add-GateResult -Name 'Analyzer' -Status 'SKIPPED' -Detail 'Skipped by explicit -SkipAnalyzer request'
  Complete-Verification -Verdict 'PARTIAL' -ExitCode 0
}

$settingsPath = Join-Path $RootPath 'PSScriptAnalyzerSettings.psd1'
if (-not (Get-Command -Name Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)) {
  Write-ErrorLine -Message 'Invoke-ScriptAnalyzer not available. Analyzer did not run.'
  Add-GateResult -Name 'Analyzer' -Status 'FAILED' -Detail 'Invoke-ScriptAnalyzer not available'
  Complete-Verification -Verdict 'FAILED' -ExitCode 2
}

if (-not (Test-Path -LiteralPath $settingsPath)) {
  Write-ErrorLine -Message "PSScriptAnalyzer settings not found: $settingsPath"
  Add-GateResult -Name 'Analyzer' -Status 'FAILED' -Detail 'Settings file missing'
  Complete-Verification -Verdict 'FAILED' -ExitCode 2
}

Write-Info -Message 'Running PSScriptAnalyzer...'
$analyzerPaths = @()
foreach ($p in @(
  (Join-Path $RootPath 'scripts'),
  (Join-Path $RootPath 'lib'),
  (Join-Path $RootPath 'tools')
)) {
  if (Test-Path -LiteralPath $p) { $analyzerPaths += $p }
}

$analyzer = @()
foreach ($path in $analyzerPaths) {
  $result = Invoke-ScriptAnalyzer -Path $path -Settings $settingsPath -Recurse -ErrorAction Continue
  if ($result) { $analyzer += $result }
}
if ($analyzer -and $analyzer.Count -gt 0) {
  Write-Warn -Message ("PSScriptAnalyzer reported {0} issue(s)." -f $analyzer.Count)
  $analyzer | Sort-Object ScriptName,Line,Column | ForEach-Object {
    Write-UiLine ("- {0}:{1}:{2} {3} ({4})" -f $_.ScriptName, $_.Line, $_.Column, $_.Message, $_.RuleName) -ForegroundColor Yellow
  }
  Add-GateResult -Name 'Analyzer' -Status 'FAILED' -Detail ("{0} issue(s)" -f $analyzer.Count)
  Complete-Verification -Verdict 'FAILED' -ExitCode 2
}
Write-Success -Message 'PSScriptAnalyzer: OK'
Add-GateResult -Name 'Analyzer' -Status 'PASS' -Detail ("{0} path(s)" -f $analyzerPaths.Count)
Complete-Verification -Verdict 'PASS' -ExitCode 0
