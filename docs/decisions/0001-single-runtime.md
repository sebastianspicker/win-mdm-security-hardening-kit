# ADR 0001: Keep one release-qualified runtime

## Status

Accepted.

## Decision

BaselineOps ships one PowerShell application. A second implementation may enter
the repository only when it replaces a complete, evidence-backed boundary in
the supported product; it may not establish a parallel catalog, schema,
dispatcher, build, or release source of truth.

## Rationale

The retired native prototype had no release-qualified capability and no runtime
relationship with the supported toolkit. Maintaining both implementations
duplicated the system model while providing no operator migration path.

The prototype nevertheless demonstrated requirements worth preserving: bounded
inputs, no-shell process execution, strict separation of intent from privileged
authority, exact package identity, short-lived elevation, authenticated local
communication, digest-bound approval, and tamper-evident action records. Future
work must prove these properties in the runtime that actually ships rather than
infer them from an adjacent implementation.
