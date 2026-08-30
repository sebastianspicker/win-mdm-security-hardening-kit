# Architecture

The supported BaselineOps product is a file-distributed PowerShell application
for inspecting and changing Windows endpoint state. It has no service,
database, plugin system, or remote control plane. Operators invoke a capability
directly, through an orchestrator, or through the Windows Forms launcher.

The repository also contains a separate, unreleased Rust v3 workspace. It has
its own schemas, applications, build, evidence ledger, and release gates. It is
not a dependency of the PowerShell application and may not claim capability
parity until its own ledger and Windows evidence close. See
[Rust v3 implementation status](rust-v3.md).

## Components and dependency direction

```text
operator -------- tools/Launcher-* runtime
   |                       |
   +-----------------------+
                           v
                scripts/00-* orchestration
                           |
                           v
scripts/NN-* capabilities ---- scripts/internal capability helpers
        |
        v
lib public application services
        |
        v
lib/platform Windows and native-process boundary
        |
        v
Windows APIs, cmdlets, fixed native tools, files, and event logs
```

- `scripts/00-*` owns selection, profile validation, dependency order,
  integrity policy, confirmation, aggregation, and process exit status.
- `scripts/01-*` through `scripts/52-*` own endpoint-specific policy,
  observation, remediation, findings, and rollback behavior. Their numbered
  filenames are stable capability identifiers and public entry points.
- `scripts/internal/` contains helpers used by one capability. It is not an
  operator surface.
- `lib/` contains behavior shared across capabilities: validation,
  configuration, execution, results, serialization, and presentation.
- `lib/platform/` contains the private implementation of executable trust,
  process control, fixed native-tool adapters, and Windows operations. The
  `External.psm1` facade is the single public module boundary for that code.
- `tools/Launcher-GUI.ps1`, `tools/Launcher-Worker.ps1`, and
  `tools/Launcher.Core.psm1` form the shipped Windows Forms runtime adapter.
  The remaining `tools/` files verify or scaffold the repository. Tool code is
  never imported by endpoint capabilities.

Dependencies flow down this list. Shared modules must not import capability
scripts, and capability-local policy must not move into a generic framework
merely because two scripts look similar.

## External contracts

The public surface comprises the 52 numbered endpoint scripts, the six `00-*`
orchestrators, their documented parameters and help, profile version 2.0, the
v2 result fields, exit codes `0`/`1`/`2`, JSON and CSV projections, example
input shapes, and the release ZIP layout. Files under `scripts/internal/`,
`scripts/_lib/`, `lib/platform/`, launcher worker arguments, and individual
module functions are same-release implementation details.

Configuration and profile documents are untrusted data. They may describe
desired state but must not grant authority to choose privileged output paths,
executables, network endpoints, or arbitrary arguments. Those decisions belong
to trusted operator parameters or protected deployment policy.

## Side-effect boundaries

Audit operations may read endpoint state and write only explicitly requested
reports or evidence. Remediation requires an explicit trusted command mode,
administrator authority where documented, and `ShouldProcess`. Elevated code
must run from an authenticated, administrator-protected package and retain the
existing path, owner, ACL, reparse-point, signature, and hash checks.

Endpoint capabilities and orchestrators launch native processes only through
the `External.psm1` boundary. That boundary resolves an exact executable,
preserves argument tokens, bounds output and execution time, and never invokes
a command shell. Direct native launch code does not belong in endpoint scripts.

The launcher owns a separate process-lifecycle boundary because it must create
the worker suspended enough to apply Windows Job Object controls and preserve
pre-start package trust checks. That code is confined to `tools/Launcher-*`,
uses `ProcessStartInfo` without a command shell, and must retain bounded output,
exact argument tokens, stop-tree behavior, and worker-protocol tests.

JSON is the lossless interchange format. CSV is a spreadsheet-safe projection
and neutralizes cells that spreadsheet applications could interpret as
formulas.

## Runtime boundaries

The supported PowerShell application and the unreleased Rust v3 prototype are
independent release lines. Each retains its own contracts and verification
evidence; neither implementation may use the other as runtime support or as a
substitute for missing release proof. The boundary is recorded in
[ADR 0001](decisions/0001-single-runtime.md).

## Verification

`tools/verify.ps1` mechanically enforces the reviewed public surface and parses
and analyzes every maintained PowerShell source. Pester protects result,
serialization, runner, trust, and selected capability contracts. CI adds
PowerShell 7.6.3, Windows PowerShell 5.1, protected-workspace, LocalSystem, and
release-package lanes that cannot be proven on a non-Windows host.
