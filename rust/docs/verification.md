# Verification and closure

Portable gates cover formatting, Clippy with warnings denied, unit/integration/doc tests, strict
schema snapshots, and dependency policy. These gates prove domain behavior only.

Release-blocking endpoint lanes require disposable Windows 11 Pro and Enterprise x64 environments
for 24H2, 25H2, and 26H1. Standard-user audit and plan, UAC apply, LocalSystem, missing features,
access denial, stale and tampered plans, reparse points, untrusted binaries, timeouts, oversized
output, and localized native-tool fixtures are explicit cases.

The release gate inventory is checked in at `release/evidence-gates.json`. An absent, renamed,
empty, or open gate blocks publication. UAC apply uses an administrator token; LocalSystem is a
separate execution-evidence lane and is not silently treated as equivalent to UAC elevation.

Every mutable capability must demonstrate plan accuracy, apply, post-apply audit, idempotent second
apply, failure injection, reboot signalling, and rollback where declared reversible. Firewall, SMB,
RDP, Defender, audit policy, logging, Sysmon, registry, and emergency isolation use snapshot VMs.
Emergency isolation additionally requires console-accessible isolated VMs. TPM, Secure Boot, and
BitLocker gates require suitable hardware or equivalent release infrastructure; absence blocks
closure and is never a silent skip.

The native GUI requires keyboard-only, high-DPI, screen-reader metadata, cancellation, progress,
artifact-opening, and UAC-transition evidence. The package process-spy test must prove that none of
the three executables starts or ships PowerShell.

The v3 release is complete only when all 52 parity-ledger entries are closed and the signed package
verifies from a protected installation. The package closure is authenticated with a detached
PKCS#7 signature over the exact `manifest.json` bytes before the manifest is parsed or trusted;
executable signatures alone do not authenticate the non-executable inventory. Runtime verification
uses the configured exact signer subject and SHA-256 pin of its canonical DER SubjectPublicKeyInfo,
a code-signing chain at the current system time, and cached revocation data. A newly provisioned
offline host can therefore fail closed when it lacks
revocation evidence, and post-certificate-expiry lifetime validation remains an open release-evidence
boundary even when the detached signature carries an external RFC 3161 timestamp. Until the signed
Windows fixtures and tamper cases close the package evidence gate, registry presence or compilation
must not be described as capability parity.
