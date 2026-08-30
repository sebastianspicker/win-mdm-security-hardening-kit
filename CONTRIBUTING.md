# Contributing

Changes to endpoint audit and remediation code can affect privileged Windows state. Keep pull requests focused, document operational impact, and add regression coverage for changed behavior.

## Development requirements

- PowerShell 7.6.3
- PSScriptAnalyzer 1.25.0
- Pester 5.8.0
- Bash for `scripts/ci-local.sh`
- Windows PowerShell 5.1 for compatibility checks
- A disposable Windows test device for changes that depend on endpoint features or remediation

## Change workflow

1. Create a branch from the intended base branch.
2. Make one focused change.
3. Add or update tests for behavior changes.
4. Update public documentation when parameters, configuration, output, security boundaries, or operation changes.
5. Run the focused tests and applicable full gates.
6. Review `git diff --check` and the complete diff.
7. Open a pull request with scope, risk, compatibility impact, and validation results.

Call out changes to profile parsing, dependency handling, remediation, integrity checks, privileged path validation, native process execution, evidence collection, or result serialization.

## Source requirements

- Follow the dependency map in `docs/architecture.md`: capability policy stays
  in its numbered script, genuinely shared behavior belongs in `lib/`, private
  platform implementation belongs in `lib/platform/`, and capability-specific
  helpers belong in `scripts/internal/`.
- Do not expose files under `scripts/internal/` or `scripts/_lib/` as operator entry points.
- Treat profiles, configuration files, paths, URLs, native output, and arguments as untrusted input.
- Preserve runner-owned mode, root, output, confirmation, signature, and hash controls.
- Implement state changes through `SupportsShouldProcess` and verify `-WhatIf` and `-Confirm` behavior.
- Do not weaken ACL, ownership, reparse-point, signature, hash, or input-validation checks to accommodate a local environment.
- Use the v2 result helpers for orchestration-compatible output.
- Avoid committing generated reports, support bundles, launcher logs, Pester XML, or other endpoint evidence.

Every maintained `.ps1` and `.psm1` file must begin with comment-based help containing `.SYNOPSIS` and `.DESCRIPTION`. Shell, JavaScript, Docker, PowerShell data, and YAML sources need a leading purpose comment where the format permits comments.

Create a numbered script scaffold with:

```powershell
pwsh -NoProfile -File .\tools\new-script.ps1 -Name 53-Example-Audit
```

Add `-SupportsRemediate` only when the script will implement guarded state changes:

```powershell
pwsh -NoProfile -File .\tools\new-script.ps1 `
  -Name 53-Example-Audit -SupportsRemediate
```

## Local checks

Run the complete PowerShell 7 gate from Bash or Git Bash:

```bash
bash ./scripts/ci-local.sh
```

The wrapper requires PowerShell Core 7.6.3. Set `PWSH_BIN` to an absolute executable path when necessary:

```bash
PWSH_BIN='/absolute/path/to/pwsh' bash ./scripts/ci-local.sh
```

Run individual PowerShell 7 checks:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\secret-scan.ps1 -RootPath .
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-Documentation.ps1 -RootPath .
pwsh -NoProfile -ExecutionPolicy Bypass -Command `
  "Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force; & .\tools\verify.ps1 -RootPath ."
pwsh -NoProfile -Command `
  "Import-Module Pester -RequiredVersion 5.8.0 -Force; Invoke-Pester -Path .\tests -CI -Output Detailed"
```

Run Windows PowerShell 5.1 compatibility checks on Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `
  "Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force; & .\tools\verify.ps1 -RootPath ."
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `
  "Import-Module Pester -RequiredVersion 5.8.0 -Force; Invoke-Pester -Path .\tests -CI -Output Detailed"
```

Standard-user Pester runs skip tests that require LocalSystem, a protected workspace, another operating system, or unavailable Windows features. Do not convert those expected environmental skips into weaker assertions.

The operator release ZIP excludes the test suite. Package checks are documented in the [release guide](docs/alpha-release.md#check-the-extracted-operator-package).

## Pull request content

A pull request should state:

- What changed and why
- Which scripts, modules, profiles, or workflows are affected
- Whether the change reads, writes, deletes, exports, launches, or stops anything
- Required privilege and Windows feature assumptions
- Compatibility impact for PowerShell 7.6.3 and Windows PowerShell 5.1
- Tests and manual validation performed
- Remaining limitations or untested platform behavior

For remediation changes, include a focused `-WhatIf` test and describe the rollback or recovery path.

## Documentation policy

Public Markdown belongs in one of these maintained locations:

- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `CHANGELOG.md`
- `docs/`
- `scripts/README.md`
- `lib/README.md`
- `examples/README.md`

Add durable documents to [docs/README.md](docs/README.md). Verify every local link with `tools/Test-Documentation.ps1`. Do not add machine-specific notes, private operational data, screenshots containing endpoint identifiers, or unverified test counts.

The reviewed `docs/` surface is allowlisted by `tools/verify.ps1`. Add any new
durable public document to the index and public-surface verifier in the same
change. Keep private or generated
material in ignored local lanes; never force-add it.

Do not report vulnerabilities in a public pull request or issue. Follow [SECURITY.md](SECURITY.md).
