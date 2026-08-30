# Release packaging and protected installation

This guide describes the tag-based GitHub release workflow and the protected Windows installation required before privileged operation. It uses `v2.3.0-alpha.1` as the concrete package example because the protected-install contract and its tests currently use that versioned directory name.

The workflow accepts semantic version tags such as `v2.3.0-alpha.1`. It must be dispatched from the tag being packaged and verifies that the event commit matches the resolved tag commit.

## Package contents

The operator ZIP contains:

- 52 numbered endpoint scripts, from prefix `01-` through prefix `52-`
- six `00-*` validation, execution, copy, and reporting entry points
- seven example profiles and four example configurations
- shared PowerShell modules and the script scaffolding/verification tools
- the Windows Forms launcher
- public project, contribution, security, changelog, and operator documentation

The ZIP excludes `.github/`, `tests/`, private directories, and `scripts/ci-local.sh`.

## Release verification

Before packaging, `.github/workflows/release.yml` performs these checks against the resolved tag:

- Installs the official PowerShell 7.6.3 Linux archive after checking its pinned SHA-256 digest.
- Loads PSScriptAnalyzer 1.25.0 and Pester 5.8.0.
- Runs the secret scan, documentation check, static verifier, and focused Pester suite.
- Builds the ZIP with `git archive` from the resolved release commit.
- Verifies the package inventory and expected counts.
- Runs profile validation, profile smoke, secret, documentation, and static checks against an extracted ZIP.

The publish job then verifies the remote tag, requires the repository's immutable-release setting, creates a build provenance attestation, creates a new draft release, uploads the assets without replacement, publishes the release, and verifies its final immutable state.

Repository files cannot prove that environment reviewers, tag rules, secrets, or immutable releases are configured on GitHub. Those controls must be checked before tagging.

## Release artifacts

For a tag named `v2.3.0-alpha.1`, the workflow creates:

- `baselineops-windows-v2.3.0-alpha.1.zip`
- `baselineops-windows-v2.3.0-alpha.1.zip.sha256`
- `baselineops-windows-v2.3.0-alpha.1.zip.manifest.sha256`
- `baselineops-windows-v2.3.0-alpha.1.zip.intoto.jsonl`

The `.sha256` file covers the ZIP. The manifest contains a SHA-256 record for every extracted file. The `.intoto.jsonl` file contains the downloaded GitHub build provenance attestation bundle. The workflow does not generate an SBOM.

### Authenticate provenance first

Download all four assets from the same GitHub release. In a standard-user
PowerShell session, copy the 40-character source commit from the release notes.
Before reading or extracting the ZIP, authenticate its digest, source commit,
source tag, and publisher workflow with GitHub CLI:

```powershell
if (-not (Get-Command gh -CommandType Application -ErrorAction SilentlyContinue)) {
  throw 'GitHub CLI with attestation verification support is required.'
}
gh attestation verify --help | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw 'GitHub CLI with attestation verification support is required.'
}
```

```powershell
$Asset = '.\baselineops-windows-v2.3.0-alpha.1.zip'
$SourceCommit = Read-Host 'Enter the 40-character source commit from the release notes'
if ($SourceCommit -notmatch '^[0-9a-fA-F]{40}$') {
  throw 'SourceCommit must be a 40-character Git commit identifier.'
}
$ExpectedSha256 = [string](& gh attestation verify $Asset `
  --repo sebastianspicker/baseline-ops `
  --bundle "$Asset.intoto.jsonl" `
  --signer-workflow github.com/sebastianspicker/baseline-ops/.github/workflows/release.yml `
  --source-ref refs/tags/v2.3.0-alpha.1 `
  --source-digest $SourceCommit `
  --deny-self-hosted-runners `
  --format json `
  --jq '.[0].verificationResult.statement.subject[0].digest.sha256')
if ($LASTEXITCODE -ne 0 -or $ExpectedSha256 -notmatch '^[0-9a-f]{64}$') {
  throw 'Release provenance verification failed.'
}
$ExpectedSha256
```

Keep the printed `$ExpectedSha256` for the protected-install step. A separately
downloaded checksum detects corruption; it does not authenticate the publisher
and is therefore checked only after the attestation.

### Verify the ZIP and extracted files

PowerShell:

```powershell
$PublishedChecksum = (Get-Content "$Asset.sha256" -Raw).Split()[0].ToLowerInvariant()
$Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Asset).Hash.ToLowerInvariant()
if ($PublishedChecksum -cne $ExpectedSha256 -or $Actual -cne $ExpectedSha256) {
  throw 'Release ZIP checksum mismatch.'
}
```

POSIX shell or Git Bash, including the extracted file manifest in a new temporary
directory:

```bash
asset='baselineops-windows-v2.3.0-alpha.1.zip'
manifest="${PWD}/${asset}.manifest.sha256"
package_dir="$(mktemp -d)"
trap 'rm -rf "${package_dir}"' EXIT
sha256sum -c "${asset}.sha256"
unzip -q "${asset}" -d "${package_dir}"
(cd "${package_dir}" && sha256sum -c "${manifest}")
```

### Check the extracted operator package

The following commands require only files included in the ZIP. Run them without
elevation from the extracted package root with PowerShell 7.6.3 exactly. This
phase validates the package but does not make a user-owned extraction safe for
privileged execution. The complete static gate also requires PSScriptAnalyzer
1.25.0 to be installed:

```powershell
pwsh -NoProfile -File .\scripts\00-Validate-Profile.ps1 -ProfilePath .\examples\profiles\baseline-audit.json -RootPath .
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\secret-scan.ps1 -RootPath .
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-Documentation.ps1 -RootPath .
pwsh -NoProfile -ExecutionPolicy Bypass -Command "Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force; & .\tools\verify.ps1 -RootPath ."
```

`verify.ps1 -SkipAnalyzer` is a partial parse-only check, not a substitute for
the complete gate. Pester and `scripts/ci-local.sh` require a full checkout
of the release tag. The operator ZIP deliberately excludes `scripts/ci-local.sh`,
`tests/`.

An extracted ZIP has no Git metadata, so the verifier and secret scan use their
recursive package fallback. In a Windows checkout, those two tools accept bare
Git only from the standard Program Files locations and enumerate
`git ls-files --cached --others --exclude-standard`. If trusted Git is absent,
the fallback can also see ignored local files; use an exact staged or package
surface for release evidence rather than weakening the executable-path policy.
The documentation checker uses the Git application found on `PATH` and
fails if repository discovery does not complete.

### Install a protected Windows copy

Elevated runners and the launcher reject any kit root or ancestor that is owned
or writable by an untrusted SID. A normal extraction below Downloads is useful
for the standard-user checks above, but it is intentionally not a privileged
execution root. `00-Copy-Local.ps1` also validates its own source before import
and is not a bootstrap from an untrusted directory. When that synchronization
tool is used, pass `-RepoRef` as the full source commit obtained from the
verified release provenance; omitted, branch, and tag references are refused
before synchronization. `-WhatIf` remains a no-mutation preview without a ref.

After successful attestation verification, open a new elevated Windows
PowerShell 5.1 session. In the block below, `$ZipPath` uses the current user's
Downloads folder. Enter the authenticated digest printed as `$ExpectedSha256`
above when prompted. The block
uses only Windows/.NET built-ins: it refuses an existing destination, copies the
ZIP into a newly protected Program Files directory, verifies that protected copy,
extracts it, and sets every extracted owner to `BUILTIN\Administrators`. Users
receive read/execute access but no write/replace access.

Copy this block from the immutable tagged GitHub page, not from a local
user-writable extraction that could have changed after verification.

```powershell
$ErrorActionPreference = 'Stop'
$Downloads = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)) 'Downloads'
$ZipPath = Join-Path $Downloads 'baselineops-windows-v2.3.0-alpha.1.zip'
$ExpectedSha256 = Read-Host 'Enter the authenticated 64-character SHA-256 digest'
$ProgramFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
if ([string]::IsNullOrWhiteSpace($ProgramFiles)) {
  throw 'Windows Program Files could not be resolved.'
}
$ProgramFilesItem = Get-Item -LiteralPath $ProgramFiles -Force -ErrorAction Stop
if (($ProgramFilesItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
  throw 'Refusing a Program Files root that is a reparse point.'
}
$InstallRoot = Join-Path $ProgramFilesItem.FullName 'BaselineOpsForWindows-v2.3.0-alpha.1'

if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
  throw 'ExpectedSha256 must be the authenticated 64-character digest.'
}
$ZipPath = (Resolve-Path -LiteralPath $ZipPath -ErrorAction Stop).Path
if (Test-Path -LiteralPath $InstallRoot) {
  throw "Refusing existing install root: $InstallRoot"
}

$AdministratorsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$SystemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$UsersSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
$Acl = New-Object System.Security.AccessControl.DirectorySecurity
$Acl.SetOwner($AdministratorsSid)
$Acl.SetAccessRuleProtection($true, $false)
$Inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
  [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$Propagation = [System.Security.AccessControl.PropagationFlags]::None
$Allow = [System.Security.AccessControl.AccessControlType]::Allow
foreach ($Entry in @(
    [pscustomobject]@{ Sid = $AdministratorsSid; Rights = [System.Security.AccessControl.FileSystemRights]::FullControl },
    [pscustomobject]@{ Sid = $SystemSid; Rights = [System.Security.AccessControl.FileSystemRights]::FullControl },
    [pscustomobject]@{ Sid = $UsersSid; Rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute }
  )) {
  $Rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
    $Entry.Sid, $Entry.Rights, $Inheritance, $Propagation, $Allow
  )
  [void]$Acl.AddAccessRule($Rule)
}

[void](New-Item -Path $InstallRoot -ItemType Directory -ErrorAction Stop)
Set-Acl -LiteralPath $InstallRoot -AclObject $Acl -ErrorAction Stop
$StagedZip = Join-Path $InstallRoot '.verified-package.zip'
try {
  Copy-Item -LiteralPath $ZipPath -Destination $StagedZip -ErrorAction Stop
  $ActualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $StagedZip).Hash
  if ($ActualSha256 -cne $ExpectedSha256.ToUpperInvariant()) {
    throw 'Protected ZIP copy does not match the authenticated digest.'
  }
  Expand-Archive -LiteralPath $StagedZip -DestinationPath $InstallRoot -ErrorAction Stop
  Remove-Item -LiteralPath $StagedZip -Force -ErrorAction Stop

  $InstalledItems = @((Get-Item -LiteralPath $InstallRoot -Force)) +
    @(Get-ChildItem -LiteralPath $InstallRoot -Recurse -Force)
  foreach ($Item in $InstalledItems) {
    if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Installed package contains a reparse point: $($Item.FullName)"
    }
    $ItemAcl = Get-Acl -LiteralPath $Item.FullName -ErrorAction Stop
    $ItemAcl.SetOwner($AdministratorsSid)
    Set-Acl -LiteralPath $Item.FullName -AclObject $ItemAcl -ErrorAction Stop
  }
} catch {
  if (Test-Path -LiteralPath $InstallRoot) {
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
  throw
}

Write-Host "Protected install ready: $InstallRoot"
```

Only after that block succeeds should an operator execute repository code with
elevation. From the protected root, the baseline profile returns `0` for success
or `2` for completed-with-warnings; exit `1` is a failure:

```powershell
Set-Location -LiteralPath $InstallRoot
pwsh -NoProfile -File .\scripts\00-Run-Profile.ps1 -ProfilePath .\examples\profiles\baseline-audit.json -RootPath $InstallRoot -Mode Audit -OutputFormat None -Confirm:$false
```

For a no-execution control-flow preview, use the strict remediation profile with
`-WhatIf`:

```powershell
pwsh -NoProfile -File .\scripts\00-Run-Profile.ps1 -ProfilePath .\examples\profiles\hardening-remediate.json -RootPath $InstallRoot -Mode Remediate -Strict -OutputFormat None -WhatIf -Confirm:$false

pwsh -NoProfile -File .\scripts\00-Run-Batch.ps1 -Category Remediation -RootPath $InstallRoot -Mode Remediate -OutputFormat None -WhatIf -Confirm:$false
```

The preview intentionally skips every child script and returns `WARN` / exit
`2`. A strict profile does not promote a warning caused only by those skips;
batch preview stops before its temporary profile workspace is created. This
confirms selection and no-mutation behavior; it is not endpoint audit or
remediation evidence. Keep `-OutputFormat None` for an artifact-free preview;
an explicitly requested JSON/CSV output path still receives the terminal
result.

## Operational limitations

- Source scripts are not Authenticode-signed. The elevated launcher requires a valid signature by default. Deployment owners must sign the scripts or explicitly record a weaker lab-only decision.
- Expected hashes supplement signature and protected-path checks. They do not make a user-writable execution root trusted.
- The interactive launcher requires environment-specific manual validation. See the [launcher checklist](launcher-gui.md#manual-validation-checklist).
- Endpoint remediation, rollback, feature availability, and failure behavior must be tested on representative disposable devices.
- Stopping a launcher worker terminates its process tree but does not undo completed changes.
- Logs, reports, support bundles, and saved launcher output can contain endpoint details.

## Maintainer release checklist

Repository files cannot enforce GitHub-hosted settings. Before tagging, enable
[immutable releases](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes),
protect release-tag creation with a repository ruleset, and configure the
`alpha-release` environment with required reviewer and deployment-tag controls.
That environment must also provide `RELEASE_SETTINGS_READ_TOKEN`, a fine-grained
token scoped to this repository with read-only Administration permission. The
publish job uses it only to confirm the immutable-release setting before it
creates a draft; the normal job token handles release contents.

1. Verify the remote controls and freeze one clean commit containing the intended source and documentation.
2. Run the commands in [CONTRIBUTING.md](../CONTRIBUTING.md#local-checks) under PowerShell 7.6.3 and Windows PowerShell 5.1 with PSScriptAnalyzer 1.25.0 and Pester 5.8.0. Review failures, unexpected skips, and test-discovery changes.
3. Complete the manual launcher and endpoint remediation checks required for the release scope.
4. Create the exact semantic prerelease tag `v2.3.0-alpha.1` at that commit and
   push only the tag intended for publication.
5. Confirm the `Release Package` workflow resolves that commit, passes every
   gate, creates the draft, uploads all four immutable assets, and publishes it.
6. Download the public assets and repeat checksum, manifest, and provenance
   verification independently.
7. Record newly discovered limitations in the changelog and this guide before
   promoting a later alpha or release candidate.

### Failed-draft recovery

The workflow deliberately refuses to reuse a release. If a run fails after it
creates an unpublished draft, preserve the run logs and inspect the draft assets
before recovery. Confirm `isDraft` is true, confirm the tag still resolves to the
frozen commit, then explicitly delete only that draft and rerun from the same
unchanged tag:

```bash
tag='v2.3.0-alpha.1'
gh release view "${tag}" --json isDraft,isImmutable,tagName,assets
gh release delete "${tag}" --yes
```

Do not pass `--cleanup-tag`; the verified tag must remain intact. Never delete
or reuse a published or immutable release. If publication state is ambiguous or
the tag moved, stop and create a new prerelease version only after review.
