# BaselineOps v3 Rust workspace

This directory contains the new, self-contained BaselineOps v3 implementation. The existing
PowerShell product remains the behavioral oracle and is not a runtime dependency of these crates.
The Rust executables never invoke PowerShell, `cmd.exe`, or another command shell.

## Support contract

The initial endpoint target is Windows 11 Pro and Enterprise x64, version 24H2 or later. Home,
Education, Server, ARM64, and older releases are outside the v3 alpha contract. Portable domain,
schema, scheduler, parser, and packaging tests run on other hosts, but Windows execution evidence
is authoritative.

## Workspace

- `baselineops-domain`: strict v3 JSON contracts, validation, digests, and exit-code mapping.
- `baselineops-windows`: path, trust, ACL, Authenticode, Windows API, and no-shell process boundary.
- `baselineops-capabilities`: compile-time registry and endpoint implementations.
- `baselineops-engine`: audit, plan, apply, journal, cancellation, reporting, and evidence control.
- `baselineops`: standard-user command-line client.
- `baselineops-gui`: native Win32 standard-user launcher.
- `baselineops-worker`: short-lived UAC-elevated apply worker.
- `xtask`: schema, parity, verification, package, manifest, and SBOM tasks.

The [parity ledger](ledger/capability-parity.json) is the implementation authority. A descriptor in the
registry proves discoverability only. A capability is complete only when its ledger entry includes
oracle tests and required Windows evidence.

## Developer commands

Run commands from this directory:

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo run -p xtask -- generate
cargo run -p xtask -- verify
```

Unsigned local builds are allowed. Release publication requires all three x64 executables to have
a valid Authenticode signature from the configured publisher, an exact Cargo-version tag, all 52
ledger entries, and every retained external evidence gate; the `rust-v*` workflow fails before
publication otherwise.

## Security boundary

Audit may write only explicitly requested reports or evidence. Plan observes state and emits an
expiring, host-bound proposal. The worker reloads inputs, independently recomputes actions, retains
the exact proposal, and requires a second operator message approving its canonical digest. The
local pipe is first-instance and ACL-restricted; both peers authenticate the other process before
exchanging bounded, nonce-linked frames. Native Authenticode, protected owner/DACL checks, UAC
launch, host binding, authenticated installed-package binding, Job Object containment, evidence
quotas, journal verification, and the pipe protocol have implementation foundations, not release
evidence. The worker refuses every mutation while protected journal composition, UAC tree
containment, capability mutators, signed signer-key fixtures, and Windows runtime evidence remain open.
Forty-seven read-only audit/plan foundations and one
fail-closed mutation foundation are `in_development`; none is marked implemented.

See [architecture.md](docs/architecture.md) and [verification.md](docs/verification.md).
