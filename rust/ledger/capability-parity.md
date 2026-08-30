# Legacy capability parity ledger

This ledger covers exactly the 52 numbered endpoint scripts. It excludes the `00-*` orchestration helpers by design. The scripts README and live PowerShell help are the evidence oracle. `legacy_only` means no Rust execution is claimed; `in_development` means native implementation work exists but semantic parity and authoritative Windows evidence are not closed.

| Legacy | Stable v3 ID | Script | Status |
| --- | --- | --- | --- |
| 01 | v3.defender.asr-allowlist | 01-ASR-Defender-Allowlist.ps1 | in_development |
| 02 | v3.laps.hygiene | 02-LAPS-Hygiene.ps1 | in_development |
| 03 | v3.local-admins.guardrail | 03-LocalAdmins-Guardrail.ps1 | in_development |
| 04 | v3.office-browser.hardening | 04-OfficeBrowser-Hardening-Proof.ps1 | in_development |
| 05 | v3.windows-update.policy | 05-WUFB-Proofing.ps1 | in_development |
| 06 | v3.update-health.ssu | 06-UpdateHealth-SSU-Proof.ps1 | in_development |
| 07 | v3.scheduled-tasks.hygiene | 07-ScheduledTasks-Hygiene.ps1 | in_development |
| 08 | v3.winget.self-heal | 08-WinGet-SelfHeal.ps1 | in_development |
| 09 | v3.support-bundle.collect | 09-SupportBundle.ps1 | legacy_only |
| 10 | v3.support-bundle.parse | 10-SupportBundle-Parser.ps1 | in_development |
| 11 | v3.defender.ioc-sweep | 11-IOC-Sweep-Defender.ps1 | legacy_only |
| 12 | v3.ir.artifact-grabber | 12-Suspicious-Artifact-Grabber.ps1 | legacy_only |
| 13 | v3.lsass.vbs-hardening | 13-LSASS-CG-HVCI-VBS.ps1 | in_development |
| 14 | v3.remote-access.guardrails | 14-SecureRemoteAccessGuardrails.ps1 | in_development |
| 15 | v3.hardware.tpm-posture | 15-HardwareTPM-Audit.ps1 | in_development |
| 16 | v3.sysmon.config | 16-Sysmon-Config-Updater.ps1 | in_development |
| 17 | v3.sysmon.rule-drift | 17-Sysmon-Rule-Drift-Sensor.ps1 | in_development |
| 18 | v3.firewall.baseline | 18-Firewall-Baseline.ps1 | in_development |
| 19 | v3.software.inventory | 19-Software-Audit.ps1 | in_development |
| 20 | v3.patch.missing | 20-MissingPatch-Notification.ps1 | in_development |
| 21 | v3.network.emergency-isolation | 21-EmergencyKillSwitch.ps1 | legacy_only |
| 22 | v3.smb.encryption | 22-SMB-Encryption-Enforcer.ps1 | in_development |
| 23 | v3.bitlocker.operations | 23-BitLocker-Operations-Audit.ps1 | in_development |
| 24 | v3.cert.autoenrollment-health | 24-Cert-AutoEnrollment-Health.ps1 | in_development |
| 25 | v3.winget.configuration | 25-WinGet-Config-Baseline-Runner.ps1 | in_development |
| 26 | v3.eventlog.fast-triage | 26-Get-WinEvent-FastTriage.ps1 | in_development |
| 27 | v3.defender.health | 27-Defender-Health-Audit.ps1 | in_development |
| 28 | v3.identity.join | 28-Join-Identity-Audit.ps1 | in_development |
| 29 | v3.network.configuration | 29-Network-Config-Audit.ps1 | in_development |
| 30 | v3.service-process.inventory | 30-Service-Process-Audit.ps1 | in_development |
| 31 | v3.powershell.logging | 31-PowerShell-Logging-Baseline.ps1 | in_development |
| 32 | v3.firewall.logging | 32-Firewall-Logging-Audit.ps1 | in_development |
| 33 | v3.advanced-audit-policy | 33-AdvancedAuditPolicy-Audit.ps1 | in_development |
| 34 | v3.time-sync.health | 34-TimeSync-Health.ps1 | in_development |
| 35 | v3.storage.reliability | 35-Storage-Reliability-Audit.ps1 | in_development |
| 36 | v3.backup.readiness | 36-Backup-Readiness-Audit.ps1 | in_development |
| 37 | v3.remote-surface.audit | 37-Remote-Surface-Audit.ps1 | in_development |
| 38 | v3.security-options.drift | 38-SecurityOptions-Drift.ps1 | in_development |
| 39 | v3.credential-guard.vbs | 39-CredentialGuard-VBS-AuditRemediate.ps1 | in_development |
| 40 | v3.lsa.protection | 40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1 | in_development |
| 41 | v3.ntlm.client | 41-NTLM-Audit-Client.ps1 | in_development |
| 42 | v3.client-security-baseline | 42-Client-SecurityBaseline-Report-IntuneRef.ps1 | in_development |
| 43 | v3.app-control.audit | 43-AppControlForBusiness-Audit.ps1 | in_development |
| 44 | v3.defender.ransomware-network-protection | 44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1 | in_development |
| 45 | v3.wef.client-readiness | 45-WEF-Client-Forwarding-Readiness-Audit.ps1 | in_development |
| 46 | v3.secure-boot.uefi | 46-SecureBoot-UEFI-Audit.ps1 | in_development |
| 47 | v3.wdag.readiness | 47-WDAG-Readiness-Audit.ps1 | in_development |
| 48 | v3.exploit-protection.audit | 48-ExploitProtection-Audit.ps1 | in_development |
| 49 | v3.driver-signing.integrity | 49-DriverSigning-Integrity-Audit.ps1 | in_development |
| 50 | v3.amsi.audit | 50-AMSI-Audit.ps1 | in_development |
| 51 | v3.applocker.audit | 51-AppLocker-Audit.ps1 | in_development |
| 52 | v3.doh.audit | 52-DoH-Audit.ps1 | in_development |

No capability is marked natively implemented. IDs 01–08, 10, 13–20, and 22–52 have native observation/evaluation or bounded audit/plan code and typed executor hooks, but remain `in_development` until their declared exclusions, semantic oracle, and Windows VM evidence close.

Capabilities 08 and 25 treat fixed App Paths registration as evidence only; executable trust and launch, package APIs, sources, repair, configuration content, installation, and apply remain excluded.

Capability 01 retains aggregate ASR-only exclusion and rule-action counts only; allowlist contents, arbitrary rules, paths, commands, synchronization, mutation, legacy oracle, and Windows client/Server VM evidence remain excluded.

Capabilities 16 and 17 retain only fixed service/image/Event Log indicators; configuration XML and effective-rule semantics, executable launch, install/update, service control, remediation, legacy oracle, and Windows VM evidence remain excluded.

Capability 02 collects no passwords and exposes no native rotation path; policy-derived thresholds are not password-expiry proof. Capability 03 accepts only canonical SID allow-list entries and observes direct members; names, allow-list files, nested expansion, and reconciliation remain excluded. Capabilities 04 and 05 expose no mutation path; their finite desired-state plans remain separate from worker-owned actions. Capability 06 treats fixed service/task state and bounded WUA history as evidence only; package/SSU proof, configurable task folders, repair, reset, restart, and mutation remain excluded. Capability 07 covers four exact task paths only; wildcard categories, general enumeration, XML, credentials, and mutation remain excluded. Capability 10 additionally needs its legacy fixture corpus retained before parity can close. Capabilities 13, 39, and 40 share one policy owner and expose registry intent only; Device Guard runtime, mutation, reboot, rollback, UEFI-lock behavior, legacy-oracle, and Windows VM evidence remain open. Capability 14 evaluates fixed local RDP and Remote Assistance values only; firewall rules, ports, groups/users, remote reachability, and mutation remain excluded. Capabilities 15, 23, and 46 additionally require physical hardware, VM, TPM, BitLocker, and UEFI/Secure Boot evidence. Capability 18 excludes logging, rules, dynamic policy stores, service control, and all mutation; policy-override and Windows VM/oracle behavior remain open. Capabilities 19, 20, and 26 additionally require Windows inventory, update-history, and Event Log evidence. Capability 22 covers three local settings only; shares, remote hosts, SMB sessions and negotiation, effective encryption, and all mutation remain excluded. Capability 24 retains only fixed policy and bounded certificate metadata; enrollment triggers, event logs, certificate bodies, private keys, enterprise-CA behavior, and mutation remain excluded. Capabilities 32, 33, and 38 exclude all mutation; capability 32 also excludes firewall-rule scope and worker actions, while capability 38 rejects the legacy arbitrary registry path/name/type schema. Capabilities 35 and 36 additionally require Windows Storage WMI provider, VSS writer, File History, and OS-volume evidence against the legacy script. Capability 37 still needs remote-reachability and legacy-oracle evidence beyond fixed SCM, registry, and local-listener indicators. Capability 42 excludes external reference files, Device Guard runtime WMI, and firewall profiles. Capability 43 excludes EFI and multi-policy enumeration, and policy content, signature, and effective-policy semantics. Capability 44 observes only fixed Defender WMI preferences and exposes no mutation; provider runtime proof, legacy-oracle comparison, and Windows client/Server VM evidence remain open. Capability 48 excludes system ASLR, CFG, SEHOP, named-image mitigation configuration, and future ASR rules beyond its fixed allowlist. Capability 49 still needs Device Guard runtime and localized BCD evidence. Capabilities 50 and 51 still need provider-publisher/effective-policy oracle and Windows evidence.

The fixed System32 tools used by capabilities 33, 34, 36, 45, 47, and 49 require protected-path, owner/DACL/ancestor, single-link, WinVerifyTrust, and exact Microsoft Windows publisher checks before launch; signed Windows runtime fixtures remain open. Capability 47 also needs Windows Pro and supported-edition VM evidence. A non-Windows host, missing requirement, unavailable operation, or missing executor returns an explicit `unsupported` outcome.
