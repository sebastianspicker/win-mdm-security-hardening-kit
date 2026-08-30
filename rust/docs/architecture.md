# Architecture and trust model

Dependencies point inward: applications depend on the engine; the engine depends on domain,
capabilities, and the Windows boundary; capabilities depend on domain and narrowly scoped Windows
adapters. Domain types do not depend on operating-system or presentation crates. The registry is
compiled into the binaries and does not load plugins, libraries, scripts, or command text at runtime.

JSON is the authoritative v3 representation. Console, JSON Lines, and flattened CSV are projections
of `ResultV3`. Every input uses a bounded UTF-8 read and a closed schema. Profiles contain typed
parameters and dependencies, never raw command lines or arbitrary executable arguments.

## Operation separation

1. `audit` observes endpoint state. Its only writes are requested report or evidence artifacts.
2. `plan` observes the same state and creates ordered typed actions with preconditions, digests,
   expiry, host binding, privilege, risk, reversibility, and reboot information.
3. `apply` uses a short-lived elevated worker. The worker does not trust the plan's action bytes: it
   reloads bounded inputs, repeats observations, and recomputes actions. It retains that exact
   proposal, returns its canonical digest for review, and accepts only a second message approving
   that digest. Capability mutation remains disabled after approval until the remaining runtime
   trust and evidence gates close.

The worker contract requires validation of its own protected installation and Authenticode signer,
a mutually authenticated ACL-restricted named pipe, a worker-retained proposal, and an append-only
action journal under `%ProgramData%\BaselineOpsForWindows`. The current alpha has foundations for
the two-phase approval, pipe authentication, and authenticated installed-package inventory, but
their signed Windows UAC/DACL/package fixtures remain open. Subject-plus-SPKI signer pinning is
implemented but lacks its signed runtime fixture. Protected journal composition and pre-execution
UAC process-tree containment are not closed. Cancellation is observed only between actions. Apply
is fail-fast. Rollback is exposed only when a capability has a tested reversible action
implementation.

## Native tools

The product does not start a command shell. A capability adapter may invoke one absolute native
executable only with an exact token policy, deadline, output caps, capability-specific parser, and
mandatory source identity. Product and vendor tools use an exact SHA-256 digest. Fixed Windows
System32 tools must remain inside the API-resolved protected System32 directory, have one hard link,
pass owner/DACL/ancestor checks and WinVerifyTrust, and match the exact Microsoft Windows publisher
subject. Timeouts and truncation are errors. APIs are preferred; tool use and localized or signed
Windows fixtures are recorded in the parity ledger.

## Release identity

Rust releases use `rust-v*` tags and cannot trigger the legacy `v*` workflow. Each release resolves
the exact tagged commit, produces signed x64 binaries, schemas, examples, documentation, an SBOM,
a per-file manifest, and SHA-256 records, and refuses to replace existing assets.
