use crate::{
    Batch, CapabilityDescriptor, ImplementationMaturity, Operations, Privilege, Reboot,
    Reversibility, Risk,
};

const A: Operations = Operations {
    audit: true,
    plan: false,
    apply: false,
};
const AP: Operations = Operations {
    audit: true,
    plan: true,
    apply: true,
};
const AUDIT_PLAN: Operations = Operations {
    audit: true,
    plan: true,
    apply: false,
};
const AUDIT: &[Batch] = &[Batch::Audit];
const AR: &[Batch] = &[Batch::Audit, Batch::Remediation];
const RU: &[Batch] = &[Batch::Remediation, Batch::Utility];
const AC: &[Batch] = &[Batch::Audit, Batch::Collection];
const C: &[Batch] = &[Batch::Collection];
const AM: &[Batch] = &[Batch::Audit, Batch::Monitoring];
const ARM: &[Batch] = &[Batch::Audit, Batch::Remediation, Batch::Monitoring];
const M: &[Batch] = &[Batch::Monitoring];
const R: &[Batch] = &[Batch::Remediation];

macro_rules! descriptor {
    ($number:literal, $id:literal, $name:literal, $script:literal, $description:literal, $wave:literal, $ops:ident, $privilege:ident, $risk:ident, $reversibility:ident, $reboot:ident, [$($requirement:literal),* $(,)?], $maturity:ident, $batches:ident) => {
        CapabilityDescriptor {
            legacy_number: $number, id: $id, display_name: $name, legacy_script: $script,
            description: $description, wave: $wave, operations: $ops,
            privilege: Privilege::$privilege, risk: Risk::$risk,
            reversibility: Reversibility::$reversibility, reboot: Reboot::$reboot,
            requirements: &[$($requirement),*], maturity: ImplementationMaturity::$maturity,
            batches: $batches,
        }
    };
}

/// The complete legacy 01 through 52 catalog. `00-*` orchestration helpers are intentionally absent.
#[rustfmt::skip]
pub static CAPABILITIES: &[CapabilityDescriptor] = &[
    descriptor!( 1, "v3.defender.asr-allowlist", "Defender and ASR allowlists", "01-ASR-Defender-Allowlist.ps1", "Audit aggregate ASR-only exclusion and fixed rule-action metadata without retaining sensitive allowlist contents; synchronization and mutation remain excluded.", 3, AUDIT_PLAN, StandardUser, High, NotApplicable, No, ["Defender WMI provider"], InDevelopment, AR ),
    descriptor!( 2, "v3.laps.hygiene", "Windows LAPS hygiene", "02-LAPS-Hygiene.ps1", "Audit fixed Windows and legacy LAPS policy and bounded Operational-event metadata; native password rotation remains unavailable.", 3, AUDIT_PLAN, StandardUser, High, NotApplicable, No, ["Windows registry", "Windows Event Log API"], InDevelopment, AR ),
    descriptor!( 3, "v3.local-admins.guardrail", "Local Administrators guardrail", "03-LocalAdmins-Guardrail.ps1", "Audit bounded direct local Administrators membership against a typed SID allow-list; nested expansion, names, files, and reconciliation remain excluded.", 3, A, StandardUser, High, NotApplicable, No, ["Windows NetAPI"], InDevelopment, AR ),
    descriptor!( 4, "v3.office-browser.hardening", "Office and browser hardening", "04-OfficeBrowser-Hardening-Proof.ps1", "Audit and plan a bounded Office 16 and Edge policy subset; Firefox and dynamic startup URLs remain excluded.", 3, AUDIT_PLAN, AdministratorRequired, Medium, Reversible, No, ["Windows registry"], InDevelopment, AR ),
    descriptor!( 5, "v3.windows-update.policy", "Windows Update policy", "05-WUFB-Proofing.ps1", "Audit and plan bounded Windows Update for Business policy values from typed desired state.", 3, AUDIT_PLAN, AdministratorRequired, High, Reversible, Possible, ["Windows registry", "Windows Update service"], InDevelopment, AR ),
    descriptor!( 6, "v3.update-health.ssu", "Update health and SSU", "06-UpdateHealth-SSU-Proof.ps1", "Collect fixed Windows Update services, two exact tasks, and bounded WUA history metadata; repair, package inspection, and mutation remain excluded.", 3, AUDIT_PLAN, StandardUser, High, NotApplicable, No, ["Windows Update Agent", "Service Control Manager", "Task Scheduler COM"], InDevelopment, AR ),
    descriptor!( 7, "v3.scheduled-tasks.hygiene", "Scheduled tasks hygiene", "07-ScheduledTasks-Hygiene.ps1", "Audit four exact critical Scheduled Tasks and retain a zero-mutation plan; wildcard categories, XML, credentials, and mutation remain excluded.", 3, AUDIT_PLAN, StandardUser, High, NotApplicable, No, ["Task Scheduler COM"], InDevelopment, AR ),
    descriptor!( 8, "v3.winget.self-heal", "WinGet self-heal", "08-WinGet-SelfHeal.ps1", "Audit fixed App Installer registration evidence and retain a zero-mutation plan; executable launch, source repair, and installation remain excluded.", 4, AUDIT_PLAN, StandardUser, Medium, NotApplicable, No, ["Windows registry"], InDevelopment, RU ),
    descriptor!( 9, "v3.support-bundle.collect", "Support bundle collection", "09-SupportBundle.ps1", "Collect diagnostics and selected event logs into a ZIP archive.", 5, A, ElevatedForApply, Medium, NotApplicable, No, ["Windows event logs", "Compress-Archive"], LegacyOnly, AC ),
    descriptor!( 10, "v3.support-bundle.parse", "Support bundle parser", "10-SupportBundle-Parser.ps1", "Validate and summarize the newest support bundle without executing its contents.", 5, A, StandardUser, Low, NotApplicable, No, [], InDevelopment, AC ),
    descriptor!( 11, "v3.defender.ioc-sweep", "Defender IOC sweep", "11-IOC-Sweep-Defender.ps1", "Check catalog-defined indicators and optionally perform containment actions.", 5, AP, ElevatedForApply, Critical, ManualRecovery, No, ["Defender PowerShell cmdlets"], LegacyOnly, AC ),
    descriptor!( 12, "v3.ir.artifact-grabber", "Suspicious artifact collection", "12-Suspicious-Artifact-Grabber.ps1", "Collect process and file artifacts into an incident-response bundle.", 5, A, ElevatedForApply, High, NotApplicable, No, ["Windows process APIs", "Windows event logs"], LegacyOnly, C ),
    descriptor!( 13, "v3.lsass.vbs-hardening", "LSASS, Credential Guard, HVCI, and VBS", "13-LSASS-CG-HVCI-VBS.ps1", "Audit and plan a fixed LSASS, Credential Guard, HVCI, VBS, and driver-blocklist registry baseline without inferring runtime state.", 3, AUDIT_PLAN, ElevatedForApply, Critical, ManualRecovery, Possible, ["Windows registry", "Device Guard"], InDevelopment, AR ),
    descriptor!( 14, "v3.remote-access.guardrails", "Secure remote access guardrails", "14-SecureRemoteAccessGuardrails.ps1", "Audit and plan a fixed local RDP and Remote Assistance registry subset; firewall, groups, remote reachability, and mutation remain excluded.", 3, AUDIT_PLAN, StandardUser, Critical, NotApplicable, No, ["Windows registry", "Remote Desktop Services"], InDevelopment, AR ),
    descriptor!( 15, "v3.hardware.tpm-posture", "Hardware TPM audit", "15-HardwareTPM-Audit.ps1", "Report TPM, Secure Boot, BitLocker, and BIOS posture.", 2, A, StandardUser, Low, NotApplicable, No, ["TBS", "WMI volume encryption", "Secure Boot APIs"], InDevelopment, AUDIT ),
    descriptor!( 16, "v3.sysmon.config", "Sysmon configuration", "16-Sysmon-Config-Updater.ps1", "Audit fixed Sysmon service, image, and Operational-event indicators and retain a zero-mutation plan; configuration XML, executable launch, install, and update remain excluded.", 4, AUDIT_PLAN, StandardUser, High, NotApplicable, No, ["Service Control Manager", "Windows Event Log API"], InDevelopment, R ),
    descriptor!( 17, "v3.sysmon.rule-drift", "Sysmon rule drift", "17-Sysmon-Rule-Drift-Sensor.ps1", "Audit fixed Sysmon service, image, and Operational-event indicators against an optional exact digest and retain a zero-mutation plan; runtime configuration retrieval and remediation remain excluded.", 4, AUDIT_PLAN, StandardUser, High, NotApplicable, No, ["Service Control Manager", "Windows Event Log API"], InDevelopment, M ),
    descriptor!( 18, "v3.firewall.baseline", "Firewall baseline", "18-Firewall-Baseline.ps1", "Audit and plan four fixed controls for Domain, Private, and Public profiles; logging, rules, policy-store selection, and mutation remain excluded.", 3, AUDIT_PLAN, StandardUser, High, Reversible, No, ["Windows Firewall API"], InDevelopment, AR ),
    descriptor!( 19, "v3.software.inventory", "Software audit", "19-Software-Audit.ps1", "Compare installed software with a catalog.", 5, A, StandardUser, Low, NotApplicable, No, ["Windows uninstall registry"], InDevelopment, AUDIT ),
    descriptor!( 20, "v3.patch.missing", "Missing patch notification", "20-MissingPatch-Notification.ps1", "Compare installed KBs with a curated JSON feed.", 5, A, StandardUser, Low, NotApplicable, No, ["Windows Update history"], InDevelopment, AC ),
    descriptor!( 21, "v3.network.emergency-isolation", "Emergency kill switch", "21-EmergencyKillSwitch.ps1", "Audit or apply host network isolation with break-glass and rollback settings.", 4, AP, ElevatedForApply, Critical, Reversible, No, ["Windows Firewall", "Task Scheduler"], LegacyOnly, R ),
    descriptor!( 22, "v3.smb.encryption", "SMB encryption", "22-SMB-Encryption-Enforcer.ps1", "Audit and plan three fixed local SMB server/client encryption controls; shares, remote negotiation, and mutation remain excluded.", 3, AUDIT_PLAN, StandardUser, High, Reversible, No, ["Windows registry"], InDevelopment, AR ),
    descriptor!( 23, "v3.bitlocker.operations", "BitLocker operations audit", "23-BitLocker-Operations-Audit.ps1", "Report BitLocker state for the operating-system volume.", 2, A, AdministratorRequired, Low, NotApplicable, No, ["WMI volume encryption"], InDevelopment, AUDIT ),
    descriptor!( 24, "v3.cert.autoenrollment-health", "Certificate autoenrollment health", "24-Cert-AutoEnrollment-Health.ps1", "Audit fixed machine AutoEnrollment policy and bounded LocalMachine/My certificate metadata; enrollment, certificate bodies, private keys, and mutation remain excluded.", 5, A, StandardUser, Medium, NotApplicable, No, ["Windows certificate store", "Windows registry"], InDevelopment, AUDIT ),
    descriptor!( 25, "v3.winget.configuration", "WinGet configuration baseline", "25-WinGet-Config-Baseline-Runner.ps1", "Audit fixed App Installer registration evidence and retain a zero-mutation plan; configuration files, executable launch, and apply remain excluded.", 4, AUDIT_PLAN, StandardUser, Medium, NotApplicable, No, ["Windows registry"], InDevelopment, RU ),
    descriptor!( 26, "v3.eventlog.fast-triage", "Windows event fast triage", "26-Get-WinEvent-FastTriage.ps1", "Query Windows event logs with bounded filters and optional export.", 5, A, StandardUser, Low, NotApplicable, No, ["Windows Event Log API"], InDevelopment, AUDIT ),
    descriptor!( 27, "v3.defender.health", "Defender health audit", "27-Defender-Health-Audit.ps1", "Report Defender service, protection, signature, and scan state.", 1, A, StandardUser, Low, NotApplicable, No, ["WinDefend service API"], InDevelopment, AUDIT ),
    descriptor!( 28, "v3.identity.join", "Join and identity audit", "28-Join-Identity-Audit.ps1", "Report host, domain or workgroup, role, and operating-system identity.", 1, A, StandardUser, Low, NotApplicable, No, ["NetJoinInformation", "ComputerName API"], InDevelopment, AUDIT ),
    descriptor!( 29, "v3.network.configuration", "Network configuration audit", "29-Network-Config-Audit.ps1", "Report per-interface IP, gateway, and DNS configuration.", 2, A, StandardUser, Low, NotApplicable, No, ["GetAdaptersAddresses"], InDevelopment, AUDIT ),
    descriptor!( 30, "v3.service-process.inventory", "Service and process audit", "30-Service-Process-Audit.ps1", "Report processes, services, resource use, and executable paths.", 2, A, StandardUser, Low, NotApplicable, No, ["Windows service APIs", "Windows process APIs"], InDevelopment, AUDIT ),
    descriptor!( 31, "v3.powershell.logging", "PowerShell logging baseline", "31-PowerShell-Logging-Baseline.ps1", "Audit and plan typed HKLM PowerShell logging policy; existing sessions may need renewal and verified Apply remains unavailable.", 3, AUDIT_PLAN, AdministratorRequired, High, Reversible, No, ["Windows registry", "PowerShell policy"], InDevelopment, AR ),
    descriptor!( 32, "v3.firewall.logging", "Firewall logging", "32-Firewall-Logging-Audit.ps1", "Audit and plan fixed-profile firewall logging from typed desired state; rule scope and mutation remain excluded.", 3, AUDIT_PLAN, AdministratorRequired, Medium, Reversible, No, ["Windows Firewall API"], InDevelopment, AR ),
    descriptor!( 33, "v3.advanced-audit-policy", "Advanced audit policy", "33-AdvancedAuditPolicy-Audit.ps1", "Audit and plan finite GUID-bound Advanced Audit Policy through protected bounded auditpol evidence.", 3, AUDIT_PLAN, AdministratorRequired, High, Reversible, No, ["auditpol.exe"], InDevelopment, AR ),
    descriptor!( 34, "v3.time-sync.health", "Time synchronization health", "34-TimeSync-Health.ps1", "Report Windows Time service, source, sync, and configuration state.", 2, A, StandardUser, Low, NotApplicable, No, ["Windows Time service", "w32tm.exe"], InDevelopment, AM ),
    descriptor!( 35, "v3.storage.reliability", "Storage reliability audit", "35-Storage-Reliability-Audit.ps1", "Report physical disks and bounded reliability counters through the Windows Storage WMI provider.", 2, A, StandardUser, Low, NotApplicable, No, ["Windows Storage WMI provider"], InDevelopment, AUDIT ),
    descriptor!( 36, "v3.backup.readiness", "Backup readiness audit", "36-Backup-Readiness-Audit.ps1", "Report OS free space, VSS-writer state, and File History indicators without mutation.", 2, A, StandardUser, Low, NotApplicable, No, ["GetDiskFreeSpaceEx", "vssadmin.exe", "Windows registry"], InDevelopment, AUDIT ),
    descriptor!( 37, "v3.remote-surface.audit", "Remote surface audit", "37-Remote-Surface-Audit.ps1", "Report local WinRM, SSH, RDP, and SMB surface indicators without asserting remote reachability.", 2, A, StandardUser, Medium, NotApplicable, No, ["SCM", "Windows registry", "IP Helper"], InDevelopment, AUDIT ),
    descriptor!( 38, "v3.security-options.drift", "Security options drift", "38-SecurityOptions-Drift.ps1", "Audit and plan six fixed HKLM DWORD security options from enum-only desired state; arbitrary registry authority and mutation are excluded.", 3, AUDIT_PLAN, AdministratorRequired, High, Reversible, Possible, ["Windows registry"], InDevelopment, ARM ),
    descriptor!( 39, "v3.credential-guard.vbs", "Credential Guard and VBS", "39-CredentialGuard-VBS-AuditRemediate.ps1", "Audit and plan finite Credential Guard and VBS registry intent while exposing missing runtime evidence.", 3, AUDIT_PLAN, AdministratorRequired, Critical, ManualRecovery, Possible, ["Windows registry", "Device Guard"], InDevelopment, AR ),
    descriptor!( 40, "v3.lsa.protection", "LSA protection", "40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1", "Audit and plan finite RunAsPPL registry intent while exposing missing runtime evidence.", 3, AUDIT_PLAN, AdministratorRequired, Critical, ManualRecovery, Required, ["Windows registry"], InDevelopment, AR ),
    descriptor!( 41, "v3.ntlm.client", "NTLM client audit", "41-NTLM-Audit-Client.ps1", "Report LAN Manager authentication-level policy.", 2, A, StandardUser, Medium, NotApplicable, No, ["Windows registry"], InDevelopment, AUDIT ),
    descriptor!( 42, "v3.client-security-baseline", "Client security baseline report", "42-Client-SecurityBaseline-Report-IntuneRef.ps1", "Report a bounded Device Guard, LSA, and PowerShell policy subset without accepting external reference files.", 2, A, StandardUser, Low, NotApplicable, No, ["Windows registry"], InDevelopment, AUDIT ),
    descriptor!( 43, "v3.app-control.audit", "App Control for Business audit", "43-AppControlForBusiness-Audit.ps1", "Report a fixed legacy Code Integrity policy-file indicator and bounded Code Integrity events; EFI, multi-policy, content, and signature semantics are excluded.", 2, A, StandardUser, Medium, NotApplicable, No, ["Windows Event Log API", "fixed Code Integrity policy file"], InDevelopment, AUDIT ),
    descriptor!( 44, "v3.defender.ransomware-network-protection", "Defender ransomware and network protection", "44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1", "Audit and plan fixed Controlled Folder Access and Network Protection preference drift; remediation remains unavailable.", 3, AUDIT_PLAN, StandardUser, High, NotApplicable, No, ["Defender WMI provider"], InDevelopment, AR ),
    descriptor!( 45, "v3.wef.client-readiness", "WEF client forwarding readiness", "45-WEF-Client-Forwarding-Readiness-Audit.ps1", "Report Windows Event Forwarding client readiness.", 2, A, StandardUser, Medium, NotApplicable, No, ["WinRM", "wecutil.exe"], InDevelopment, AUDIT ),
    descriptor!( 46, "v3.secure-boot.uefi", "Secure Boot and UEFI audit", "46-SecureBoot-UEFI-Audit.ps1", "Report Secure Boot and UEFI state.", 2, A, StandardUser, Low, NotApplicable, No, ["GetFirmwareType", "Secure Boot state registry"], InDevelopment, AUDIT ),
    descriptor!( 47, "v3.wdag.readiness", "WDAG readiness audit", "47-WDAG-Readiness-Audit.ps1", "Report Windows Defender Application Guard readiness from fixed feature, policy, edition, and virtualization evidence.", 2, A, StandardUser, Low, NotApplicable, No, ["DISM", "Windows Defender Application Guard feature", "GetProductInfo"], InDevelopment, AUDIT ),
    descriptor!( 48, "v3.exploit-protection.audit", "Exploit protection audit", "48-ExploitProtection-Audit.ps1", "Report machine DEP and a fixed allowlist of Defender ASR policy indicators while exposing unsupported mitigation evidence.", 2, A, StandardUser, Medium, NotApplicable, No, ["GetSystemDEPPolicy", "Windows registry"], InDevelopment, AUDIT ),
    descriptor!( 49, "v3.driver-signing.integrity", "Driver signing and code integrity audit", "49-DriverSigning-Integrity-Audit.ps1", "Report fixed current-loader BCD integrity flags and HVCI registry intent without inferring runtime state.", 2, A, StandardUser, High, NotApplicable, No, ["bcdedit.exe", "Windows registry"], InDevelopment, AUDIT ),
    descriptor!( 50, "v3.amsi.audit", "AMSI audit", "50-AMSI-Audit.ps1", "Report fixed AMSI provider, bypass, logging, and script-host registry indicators.", 2, A, StandardUser, High, NotApplicable, No, ["Windows registry", "AMSI"], InDevelopment, AUDIT ),
    descriptor!( 51, "v3.applocker.audit", "AppLocker audit", "51-AppLocker-Audit.ps1", "Report fixed AppLocker registry collections and Application Identity service state.", 2, A, StandardUser, Medium, NotApplicable, No, ["Windows registry", "Application Identity service"], InDevelopment, AUDIT ),
    descriptor!( 52, "v3.doh.audit", "DNS-over-HTTPS audit", "52-DoH-Audit.ps1", "Report Windows DNS-over-HTTPS client configuration.", 2, A, StandardUser, Low, NotApplicable, No, ["Windows DNS client"], InDevelopment, AUDIT ),
];
