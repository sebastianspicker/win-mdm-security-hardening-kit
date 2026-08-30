# BaselineOps for Windows

BaselineOps for Windows is a collection of PowerShell scripts for auditing Windows endpoint configuration, collecting diagnostic evidence, detecting drift, and applying selected configuration changes. It is intended for endpoint administrators and security engineers working with Windows devices, including devices managed through MDM.

The repository contains individual endpoint scripts, profile and batch runners, shared PowerShell modules, example JSON inputs, a Windows Forms launcher, verification tools, and automated tests. It also contains the separate, unreleased Rust v3 workspace described in [docs/rust-v3.md](docs/rust-v3.md). The Rust workspace does not replace or run inside the supported PowerShell application. The PowerShell application does not install or run a background service.

## Project scope

The numbered scripts cover Microsoft Defender, Attack Surface Reduction, Windows Firewall, BitLocker, LAPS, Credential Guard, VBS, HVCI, LSA protection, AppLocker, App Control for Business, PowerShell logging, Windows Update, WinGet, Sysmon, remote access, event logs, storage, backup readiness, identity, and related endpoint state.

The toolkit supports three execution patterns:

- Run a numbered script directly for script-specific parameters.
- Run one script through `scripts/00-Run-Local.ps1` for path and integrity checks.
- Run an ordered JSON profile or a curated batch through the orchestration layer.

See the [script catalog](scripts/README.md) for the complete list.

## Current capabilities and limitations

Current capabilities:

- 52 numbered endpoint scripts and six `00-*` orchestration, copy, validation, and reporting scripts
- Audit, collection, monitoring, and selected remediation operations
- Console output and a shared v2 result object for JSON, CSV, and pipeline use
- Profile validation, dependency ordering, strict result handling, signature checks, and SHA-256, SHA-384, or SHA-512 hash checks
- Seven example profiles and four script-specific configuration examples
- A Windows Forms launcher for individual scripts and profiles
- PowerShell parsing, PSScriptAnalyzer, Pester, documentation, and secret-scan automation

Limitations:

- Endpoint scripts depend on Windows APIs, commands, features, editions, and privileges. Unsupported or unavailable features produce script-specific warnings or failures.
- Remediation exists only in scripts listed for the batch runner's `Remediation` category or otherwise documented by the target script. Review the script help and code before using it.
- Audit and collection operations can write reports, logs, archives, or other evidence. Audit mode is not a general no-write mode.
- Profile JSON cannot pass arguments to child scripts. `Steps[].Args` must be empty.
- A profile cannot activate remediation by declaring `Defaults.Mode` as `Remediate`. The trusted runner command must include `-Mode Remediate`.
- `Defaults.OutputFormat` and `Defaults.OutputPath` are validated but ignored by the runner. Use runner command-line parameters for output.
- `-WhatIf` on a profile or batch previews orchestration without executing child scripts. It does not inspect endpoint state and returns warning exit code `2` because steps were skipped.
- The source files are not Authenticode-signed.
- The Windows Forms launcher has automated policy and worker tests, but its interactive accessibility, scaling, and endpoint-remediation behavior still requires manual validation. See the [launcher guide](docs/launcher-gui.md).
- Windows endpoint behavior varies by operating system and installed feature. Validate the selected scripts and rollback procedure on disposable test devices before deployment.

## Requirements

Operator requirements:

- Windows with the APIs and features required by the selected script
- PowerShell 7.6.3 for the primary PowerShell Core path, or Windows PowerShell 5.1 for the compatibility path
- Administrator rights for most remediation operations and some audits
- Script-specific components such as Microsoft Defender, BitLocker, WinGet, or Sysmon

Launcher requirements:

- Windows Forms
- Windows PowerShell 5.1 with .NET Framework 4.8, or PowerShell 7.6.3
- An elevated process to select Remediate mode

Development requirements:

- PowerShell 7.6.3
- PSScriptAnalyzer 1.25.0
- Pester 5.8.0
- Bash for `scripts/ci-local.sh`
- Windows PowerShell 5.1 for the compatibility gates
- A recent Rust toolchain for the Rust v3 workspace

Earlier PowerShell Core versions are not part of the repository's verified toolchain.

## Installation

### Source checkout

Clone the repository for development and standard-user inspection:

```powershell
git clone https://github.com/sebastianspicker/baseline-ops.git baselineops-windows
Set-Location -LiteralPath .\baselineops-windows
```

Install the pinned development modules in the current user's module path if they are absent:

```powershell
Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Scope CurrentUser
Install-Module Pester -RequiredVersion 5.8.0 -Scope CurrentUser -SkipPublisherCheck
```

Do not run privileged scripts from a user-owned checkout or Downloads extraction. Elevated runners validate the toolkit root and its ancestors before importing repository code. For privileged operation, authenticate a release package and install it in a protected directory as described in the [release and deployment guide](docs/alpha-release.md#install-a-protected-windows-copy).

### Extracted release ZIP

Run package validation without elevation from the extracted package root. These checks inspect the package but do not create a trusted location for privileged execution:

```powershell
pwsh -NoProfile -File .\scripts\00-Validate-Profile.ps1 `
  -ProfilePath .\examples\profiles\baseline-audit.json -RootPath .

pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\secret-scan.ps1 -RootPath .
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-Documentation.ps1 -RootPath .
pwsh -NoProfile -ExecutionPolicy Bypass -Command `
  "Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force; & .\tools\verify.ps1 -RootPath ."
```

The operator ZIP excludes `tests/`, `.github/`, and `scripts/ci-local.sh`.

## Configuration

Configuration is script-specific. The files under `examples/configs/` are direct inputs to named script parameters:

| File | Script | Parameter |
| --- | --- | --- |
| `asr-defender-allowlist.json` | `01-ASR-Defender-Allowlist.ps1` | `-ExceptionsPath` |
| `local-admins-allowlist.json` | `03-LocalAdmins-Guardrail.ps1` | `-AllowListPath` |
| `firewall-baseline.json` | `18-Firewall-Baseline.ps1` | `-CatalogPath` |
| `wufb-proofing.json` | `05-WUFB-Proofing.ps1` | `-CatalogPath` |

These files are examples, not organizational policy. The allow lists and custom firewall rules are empty. Target release pinning and active hours are disabled in the Windows Update example. Copy and review a file before using it for remediation.

`-ConfigPath` is a separate wrapper configuration mechanism used by individual scripts. A wrapper can point to the direct inputs above through script-specific keys. See [examples/README.md](examples/README.md) for those keys.

Profiles under `examples/profiles/` have this shape:

```json
{
  "ProfileName": "example",
  "Version": "2.0",
  "Defaults": {
    "Mode": "Audit",
    "Strict": false,
    "OutputFormat": "Console",
    "OutputPath": null
  },
  "Steps": [
    {
      "Script": "27-Defender-Health-Audit.ps1",
      "Args": [],
      "ContinueOnError": false,
      "DependsOn": []
    }
  ],
  "Integrity": {
    "RequireSigned": false,
    "ExpectedHashes": {}
  }
}
```

Script names must resolve under `scripts/`, may not reference `00-*` control scripts, and may not repeat. Dependencies must name other steps in the same profile. Profile files are limited to 1 MiB by the validator.

## Usage

Run a read-only Defender health audit:

```powershell
.\scripts\27-Defender-Health-Audit.ps1
```

Return its structured result to the pipeline:

```powershell
$result = .\scripts\27-Defender-Health-Audit.ps1 -PassThru
$result | ConvertTo-Json -Depth 6
```

Validate and run an example profile:

```powershell
pwsh -NoProfile -File .\scripts\00-Validate-Profile.ps1 `
  -ProfilePath .\examples\profiles\baseline-audit.json -RootPath .

pwsh -NoProfile -File .\scripts\00-Run-Profile.ps1 `
  -ProfilePath .\examples\profiles\baseline-audit.json `
  -RootPath . -Mode Audit -OutputFormat None -Confirm:$false
```

Run one script through the local runner:

```powershell
pwsh -NoProfile -File .\scripts\00-Run-Local.ps1 `
  -ScriptName 27-Defender-Health-Audit.ps1 -RootPath . `
  -Mode Audit -OutputFormat Console
```

Preview a remediation profile without running child scripts:

```powershell
pwsh -NoProfile -File .\scripts\00-Run-Profile.ps1 `
  -ProfilePath .\examples\profiles\hardening-remediate.json `
  -RootPath . -Mode Remediate -Strict -OutputFormat None `
  -WhatIf -Confirm:$false
```

The preview returns exit `2`. `-Confirm:$false` alone is not a dry run.

Batch categories are `All`, `Audit`, `Remediation`, `Collection`, `Utility`, and `Monitoring`:

```powershell
pwsh -NoProfile -File .\scripts\00-Run-Batch.ps1 `
  -Category Audit -RootPath . -Mode Audit -OutputFormat None `
  -ContinueOnError -Confirm:$false
```

Start the optional launcher from a protected installation:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Launcher-GUI.ps1
```

Use `Get-Help` for a script's complete parameter contract:

```powershell
Get-Help .\scripts\18-Firewall-Baseline.ps1 -Full
```

## Output and exit codes

Scripts using the shared v2 result contract return these top-level fields: `SchemaVersion`, `ScriptName`, `Mode`, `ComputerName`, `TimestampUtc`, `Result`, `Findings`, `Summary`, and `Metadata`.

The orchestration layer maps results to process exit codes:

| Exit code | Meaning |
| --- | --- |
| `0` | Completed with result `OK` |
| `1` | Failed with result `FAIL` |
| `2` | Completed with result `WARN` |

`-OutputFormat` accepts `Console`, `Json`, `Csv`, or `None`. Use `-OutputPath` for JSON or CSV output. Use `-PassThru` to emit the result object. Script-specific exports may use parameters such as `-ExportPath`, `-AuditPath`, or `-ProofPath` instead.

## Repository structure

```text
.
|-- .github/            GitHub Actions, issue templates, and repository policy
|-- docs/               Release, operation, and launcher documentation
|-- examples/
|   |-- configs/        Script-specific JSON examples
|   `-- profiles/       Orchestration profiles
|-- lib/                Shared PowerShell modules
|-- rust/               Separate, unreleased Rust v3 workspace
|-- scripts/
|   |-- _lib/           Common script bootstrap
|   `-- internal/       Script-specific helpers, not operator entry points
|-- tests/              Focused Pester regression tests
|-- tools/              Verification, scaffolding, secret scan, and launcher files
`-- PSScriptAnalyzerSettings.psd1
```

## Development workflow

1. Create a branch from the intended base.
2. Make one focused change and add or update tests for behavior changes.
3. Use shared modules under `lib/` instead of duplicating cross-script behavior.
4. Run the focused test file, then the complete local checks that apply to the change.
5. Inspect `git diff --check` and the final diff.
6. Open a pull request that describes scope, operational risk, and validation performed.

Use `tools/new-script.ps1` when adding a numbered script:

```powershell
pwsh -NoProfile -File .\tools\new-script.ps1 -Name 53-Example-Audit
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for source, test, and documentation requirements.

## Testing

Run the complete PowerShell 7 gate from Bash or Git Bash:

```bash
bash ./scripts/ci-local.sh
```

The wrapper requires PowerShell Core 7.6.3, installs missing PSScriptAnalyzer 1.25.0 and Pester 5.8.0 in the current-user scope, runs the secret scan, runs static verification, and runs Pester. Set `PWSH_BIN` to an absolute PowerShell 7.6.3 executable path when it is not available as `pwsh`:

```bash
PWSH_BIN='/absolute/path/to/pwsh' bash ./scripts/ci-local.sh
```

Run gates separately from PowerShell:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\secret-scan.ps1 -RootPath .
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-Documentation.ps1 -RootPath .
pwsh -NoProfile -ExecutionPolicy Bypass -Command `
  "Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force; & .\tools\verify.ps1 -RootPath ."
pwsh -NoProfile -Command `
  "Import-Module Pester -RequiredVersion 5.8.0 -Force; Invoke-Pester -Path .\tests -CI -Output Detailed"
```

Run the Windows PowerShell 5.1 compatibility checks on Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `
  "Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force; & .\tools\verify.ps1 -RootPath ."
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `
  "Import-Module Pester -RequiredVersion 5.8.0 -Force; Invoke-Pester -Path .\tests -CI -Output Detailed"
```

`PWSH_BIN` must resolve to PowerShell 7.6.3 for the supported test contract. Standard-user test runs skip cases that require LocalSystem, protected workspace ownership, unavailable Windows features, or another operating system. CI contains separate Windows, Windows PowerShell 5.1, LocalSystem, and Linux smoke lanes.

Run the Rust v3 workspace gates separately:

```bash
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo run -p xtask -- verify
```

These gates validate the prototype workspace. They do not establish capability
parity or release qualification; see [Rust v3 implementation status](docs/rust-v3.md).

## Deployment and operation

The release workflow runs for semantic version tags matching `v*`, validates the resolved tag, runs the pinned verification suites, and creates `baselineops-windows-<tag>.zip`. It excludes development-only files from the operator package, generates ZIP and per-file SHA-256 records, creates a GitHub build provenance attestation, and publishes the release after checking repository release controls.

Deployment is file-based. There is no installer, daemon, or scheduled service in the repository. Authenticate the release assets, install the extracted files under a protected Windows directory, then invoke scripts or the launcher from that directory. See [docs/alpha-release.md](docs/alpha-release.md) for the workflow contract and protected installation procedure.

For operation:

- Start with Audit mode on a disposable device.
- Review script-specific inputs and output paths.
- Use `-WhatIf` for state-changing scripts that implement `ShouldProcess`.
- Treat exit `2` as a completed run that requires review, not as success equivalent to exit `0`.
- Rerun Audit after remediation. Stopping a process does not roll back completed changes.

## Troubleshooting

`PowerShell runtime drift`

: Use PowerShell 7.6.3. If it is installed outside `PATH`, set `PWSH_BIN` to its absolute executable path for `scripts/ci-local.sh`.

`PSScriptAnalyzer 1.25.0 is unavailable`

: Install the exact module version. `tools/verify.ps1 -SkipAnalyzer` performs parsing only and is not the complete static gate.

Exit code `2`

: Inspect warnings and findings. This is also the expected result for profile and batch `-WhatIf` previews because no child steps execute.

Elevated runner rejects the toolkit root

: The root or an ancestor is owned or writable by an untrusted SID, or contains a reparse point. Use the protected installation procedure. Do not relax the check or run privileged code from Downloads.

Elevated launcher rejects unsigned scripts

: The launcher enables `Require valid signature` by default when elevated. Sign the scripts according to the deployment trust policy. A lab-only opt-out weakens this check and does not make a user-writable root trusted.

Profile validation rejects `Args`

: Profile arguments are intentionally disabled. Run the target through `00-Run-Local.ps1` or invoke it directly with trusted command-line arguments.

Documentation or secret scanning includes ignored local files

: On Windows, the verifier and secret scanner accept bare Git only from standard Program Files locations. Without trusted Git they use recursive package discovery. Run release evidence against a clean staged surface or extracted package.

## Security considerations

- Treat profiles, configuration files, script arguments, and downloaded artifacts as untrusted input.
- Authenticate release provenance and checksums before privileged installation.
- Do not execute elevated repository code from a user-owned or user-writable directory.
- Use `-RequireSigned` or `-ExpectedHash` where the deployment model supplies trusted signatures or hashes.
- Review every remediation path, required privilege, reboot effect, and rollback procedure before use.
- Store JSON, CSV, logs, support bundles, launcher output, and test XML as sensitive endpoint data.
- Do not commit credentials, tokens, private keys, endpoint evidence, or unredacted logs.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Contributing

Contributions should include focused tests and documentation for changed behavior. Run the relevant PowerShell 7.6.3 checks and, for Windows-sensitive changes, the Windows PowerShell 5.1 compatibility checks. Do not weaken path, ACL, signature, hash, confirmation, or input-validation controls to make a test pass.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Documentation

- [Documentation index](docs/README.md)
- [Architecture](docs/architecture.md)
- [Rust v3 implementation status](docs/rust-v3.md)
- [Release and deployment guide](docs/alpha-release.md)
- [Launcher guide](docs/launcher-gui.md)
- [Script catalog](scripts/README.md)
- [Configuration and profile examples](examples/README.md)
- [Shared module reference](lib/README.md)
- [Security policy](SECURITY.md)
- [Contribution guide](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [MIT license](LICENSE)
