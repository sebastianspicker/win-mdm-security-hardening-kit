# ADR 0001: Keep release lines isolated

## Status

Accepted.

## Decision

BaselineOps keeps the supported PowerShell application and the unreleased Rust
v3 workspace as independent release lines. Each implementation owns its own
catalog, schemas, dispatcher, build, verification evidence, and release gates.
Neither implementation is a runtime dependency of the other, and evidence from
one may not qualify capability or release claims for the other.

## Rationale

The PowerShell application remains the supported behavioral oracle and release
line. Rust v3 is a substantial successor prototype whose capability ledger and
Windows evidence are not closed. Keeping the boundaries explicit preserves the
new direction without presenting partial native foundations as shipped parity.

Both lines retain the same security expectations: bounded inputs, no-shell
process execution, strict separation of intent from privileged authority, exact
package identity, short-lived elevation, authenticated local communication,
digest-bound approval, and tamper-evident action records. Each runtime must
prove those properties through its own implementation and evidence.
