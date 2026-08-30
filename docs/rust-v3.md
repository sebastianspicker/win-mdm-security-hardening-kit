# Rust v3 implementation

The self-contained Rust rewrite is developed under [`rust/`](../rust/README.md). It is additive:
the existing PowerShell product remains the supported behavioral oracle and release line.

Rust releases use separate `rust-v*` tags and separate CI/release workflows. Registry presence does
not mean native parity. The checked-in [capability ledger](../rust/ledger/capability-parity.md) records
the implementation and evidence state for every legacy endpoint capability.

The v3 package targets Windows 11 Pro and Enterprise x64, version 24H2 or later. Publication requires
all 52 capabilities and every retained external evidence gate to close, an exact `rust-v<Cargo
version>` tag, and all three executables to pass Authenticode subject and public-key pin
verification. The package inventory is anchored by a detached PKCS#7 signature over its exact
manifest bytes. Schemas, SBOM,
protected-install checks, and the remaining current-time/offline trust evidence are described in the
[verification contract](../rust/docs/verification.md). The release workflow currently refuses
publication because those capability and Windows evidence gates are not closed.
