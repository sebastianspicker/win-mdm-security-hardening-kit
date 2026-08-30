# Shared PowerShell modules

The modules in `lib/` provide common validation, execution, output, and Windows API wrappers. Numbered scripts load the repository module path through `scripts/_lib/Bootstrap.ps1` and import only the modules they need.

## Module Index

| Module | Responsibility |
| --- | --- |
| `Common.psm1` | Caller-scope access, administrator checks, arrays, directory creation, property checks, and safe file names |
| `Config.psm1` | JSON configuration loading, default merging, metadata, and object-to-hashtable conversion |
| `Console.psm1` | Finding-oriented console summaries, severity styles, and statistics |
| `EventLog.psm1` | Event source creation and health-event writes |
| `Evidence.psm1` | Environment expansion, SHA-256 calculation, and evidence copies |
| `Execution.psm1` | Argument-token parsing and bounded child-script execution |
| `External.psm1` | Stable facade for native command execution and Windows command-line tools |
| `JsonInput.psm1` | Private bounded UTF-8 JSON read and parse primitive for shared adapters |
| `JsonCatalog.psm1` | JSON catalog reads with status or data-only return values |
| `Output.psm1` | Capture-friendly sections, key/value lines, warnings, and status output |
| `Registry.psm1` | Registry reads, writes, existence checks, and removal helpers |
| `Results.psm1` | Finding collections and finding object construction |
| `Serialization.psm1` | v2 results, exit codes, JSON and CSV serialization, and output path validation |
| `Validation.psm1` | Script-name, Git reference, URL, bounded-file, traversal, reparse-point, and Windows ACL validation |

## Usage

Load the bootstrap before importing repository modules from a numbered script:

```powershell
. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force
```

Use these boundaries when adding shared behavior:

- Use `Output.psm1` for generic console text.
- Use `Console.psm1` for finding summaries and severity presentation.
- Use `Results.psm1` to create finding objects and collections.
- Use `Serialization.psm1` for final v2 results and JSON or CSV output.
- Use `Execution.psm1` for child PowerShell invocation through the runner path.
- Use `External.psm1` for bounded native process calls and Windows command wrappers.
- Use `Validation.psm1` for untrusted names, paths, references, URLs, and bounded text files.
- `JsonInput.psm1` is the low-level bounded UTF-8 JSON primitive; keep caller-specific fallback and status behavior in its adapter.
- Use `Config.psm1` or `JsonCatalog.psm1` instead of direct, repeated JSON-loading code.

Do not add a second implementation of path validation, native process capture, result serialization, or finding creation inside an endpoint script.

`External.psm1` keeps the public command contract in one place and dot-sources
focused private implementations from `lib/platform/`: executable resolution and
trust, the isolated native process boundary, fixed native-tool adapters, and
event-log, scheduled-task, and registry operations. Import `External.psm1`,
not an implementation file.

## v2 result object

`Get-V2ResultObject` in `Serialization.psm1` creates the orchestration result:

| Field | Value |
| --- | --- |
| `SchemaVersion` | `2.0` |
| `ScriptName` | Script filename |
| `Mode` | `Audit` or `Remediate` |
| `ComputerName` | Target host name |
| `TimestampUtc` | UTC execution timestamp |
| `Result` | `OK`, `WARN`, or `FAIL` |
| `Findings` | Array of finding objects |
| `Summary` | Script-specific result summary |
| `Metadata` | Script-specific metadata |

`Get-V2ExitCode` maps `OK` to `0`, `FAIL` to `1`, and `WARN` to `2`. `Write-ResultObject` writes the selected `Console`, `Json`, `Csv`, or `None` format. `ConvertTo-V2Json` provides consistent JSON serialization.

## Finding object

The shared finding helpers create objects with at least `Code`, `Severity`, and `Message`:

```json
{
  "Code": "DEF-AMServiceDisabled",
  "Severity": "High",
  "Message": "Defender AM Service is not enabled."
}
```

Scripts can attach additional fields through the finding helper's `-Extra` parameter.

Finding codes use a domain prefix followed by a descriptive identifier, such as `DEF-`, `FW-`, `LAPS-`, `CG-`, `LSA-`, `WEF-`, or `APPLOCK-`. The complete set is defined by the scripts and is not a closed enum.

Severities used by the shared helpers include `Critical`, `High`, `Medium`, `Low`, `Info`, `OK`, and `Pass`. Consumers should use the top-level `Result` for process-level status and retain finding severity for detailed analysis.
