use crate::*;

#[test]
fn registry_contains_exactly_the_legacy_leaf_scripts() {
    assert_eq!(list().len(), 52);
    for (index, descriptor) in list().iter().enumerate() {
        assert_eq!(
            descriptor.legacy_number,
            u8::try_from(index + 1).expect("the registry has fewer than 256 entries")
        );
        assert!(descriptor.id.starts_with("v3."));
        assert_eq!(descriptor.id, descriptor.id.to_ascii_lowercase());
        assert!(
            descriptor
                .legacy_script
                .starts_with(&format!("{:02}-", index + 1))
        );
        assert!(!descriptor.legacy_script.starts_with("00-"));
    }
}

#[test]
fn wave_one_descriptors_have_explicit_executor_hooks() {
    for id in ["v3.defender.health", "v3.identity.join"] {
        let descriptor = lookup(id).expect("wave one descriptor");
        assert_eq!(descriptor.wave, 1);
        assert_eq!(descriptor.maturity, ImplementationMaturity::InDevelopment);
    }
}

#[test]
fn wef_time_descriptors_have_read_only_development_hooks() {
    for id in ["v3.time-sync.health", "v3.wef.client-readiness"] {
        let descriptor = lookup(id).expect("WEF/time descriptor");
        assert_eq!(descriptor.wave, 2);
        assert_eq!(descriptor.maturity, ImplementationMaturity::InDevelopment);
        assert!(descriptor.operations.audit);
        assert!(!descriptor.operations.apply);
    }
}

#[test]
fn app_control_descriptor_is_a_bounded_read_only_development_hook() {
    let descriptor = lookup("v3.app-control.audit").expect("App Control descriptor");
    assert_eq!(descriptor.legacy_number, 43);
    assert_eq!(descriptor.maturity, ImplementationMaturity::InDevelopment);
    assert!(descriptor.operations.audit);
    assert!(!descriptor.operations.plan && !descriptor.operations.apply);
    assert!(descriptor.description.contains("EFI"));
    assert!(descriptor.description.contains("signature"));
}

#[test]
fn storage_backup_descriptors_have_read_only_development_hooks() {
    for id in ["v3.storage.reliability", "v3.backup.readiness"] {
        let descriptor = lookup(id).expect("storage/backup descriptor");
        assert_eq!(descriptor.wave, 2);
        assert_eq!(descriptor.maturity, ImplementationMaturity::InDevelopment);
        assert!(descriptor.operations.audit);
        assert!(!descriptor.operations.plan && !descriptor.operations.apply);
    }
}

#[test]
fn inventory_wave_descriptors_have_read_only_development_hooks() {
    for id in [
        "v3.software.inventory",
        "v3.patch.missing",
        "v3.eventlog.fast-triage",
    ] {
        let descriptor = lookup(id).expect("inventory descriptor");
        assert_eq!(descriptor.wave, 5);
        assert_eq!(descriptor.maturity, ImplementationMaturity::InDevelopment);
        assert!(descriptor.operations.audit);
        assert!(!descriptor.operations.plan);
        assert!(!descriptor.operations.apply);
    }
}

#[test]
fn network_service_descriptors_have_read_only_development_hooks() {
    for id in ["v3.network.configuration", "v3.service-process.inventory"] {
        let descriptor = lookup(id).expect("network/service descriptor");
        assert_eq!(descriptor.wave, 2);
        assert_eq!(descriptor.maturity, ImplementationMaturity::InDevelopment);
        assert!(descriptor.operations.audit);
        assert!(!descriptor.operations.plan && !descriptor.operations.apply);
    }
}

#[test]
fn remote_and_wdag_descriptors_have_read_only_development_hooks() {
    for id in ["v3.remote-surface.audit", "v3.wdag.readiness"] {
        let descriptor = lookup(id).expect("remote/WDAG descriptor");
        assert_eq!(descriptor.wave, 2);
        assert_eq!(descriptor.maturity, ImplementationMaturity::InDevelopment);
        assert!(descriptor.operations.audit);
        assert!(!descriptor.operations.plan && !descriptor.operations.apply);
    }
}

#[test]
fn support_bundle_parser_is_read_only_and_in_development() {
    let descriptor = lookup("v3.support-bundle.parse").expect("support-bundle descriptor");
    assert_eq!(descriptor.legacy_number, 10);
    assert_eq!(descriptor.maturity, ImplementationMaturity::InDevelopment);
    assert!(descriptor.operations.audit);
    assert!(!descriptor.operations.plan && !descriptor.operations.apply);
}

#[test]
fn powershell_logging_descriptor_remains_in_development() {
    let descriptor = lookup("v3.powershell.logging").expect("PowerShell logging descriptor");
    assert_eq!(descriptor.legacy_number, 31);
    assert_eq!(descriptor.maturity, ImplementationMaturity::InDevelopment);
    assert!(descriptor.operations.audit && descriptor.operations.plan);
    assert!(!descriptor.operations.apply);
    assert_eq!(descriptor.privilege, Privilege::AdministratorRequired);
    assert_eq!(descriptor.reboot, Reboot::No);
}

#[test]
fn firewall_logging_descriptor_is_a_drift_only_development_hook() {
    let descriptor = lookup("v3.firewall.logging").expect("firewall logging descriptor");
    assert_eq!(descriptor.legacy_number, 32);
    assert_eq!(descriptor.maturity, ImplementationMaturity::InDevelopment);
    assert!(descriptor.operations.audit && descriptor.operations.plan);
    assert!(!descriptor.operations.apply);
    assert_eq!(descriptor.requirements, ["Windows Firewall API"]);
}

#[test]
fn office_and_windows_update_descriptors_are_typed_development_hooks() {
    for (id, reboot) in [
        ("v3.office-browser.hardening", Reboot::No),
        ("v3.windows-update.policy", Reboot::Possible),
    ] {
        let descriptor = lookup(id).expect("policy descriptor");
        assert_eq!(descriptor.maturity, ImplementationMaturity::InDevelopment);
        assert_eq!(descriptor.privilege, Privilege::AdministratorRequired);
        assert_eq!(descriptor.reversibility, Reversibility::Reversible);
        assert_eq!(descriptor.reboot, reboot);
        assert!(descriptor.operations.audit && descriptor.operations.plan);
        assert!(!descriptor.operations.apply);
    }
}

#[test]
fn laps_and_security_options_are_plan_only_development_hooks() {
    for id in ["v3.laps.hygiene", "v3.security-options.drift"] {
        let descriptor = lookup(id).expect("bounded policy descriptor");
        assert_eq!(descriptor.maturity, ImplementationMaturity::InDevelopment);
        assert!(descriptor.operations.audit && descriptor.operations.plan);
        assert!(!descriptor.operations.apply);
    }
}

#[test]
fn local_admins_and_defender_ransomware_are_bounded_development_hooks() {
    let local_admins = lookup("v3.local-admins.guardrail").expect("local admins descriptor");
    assert_eq!(local_admins.maturity, ImplementationMaturity::InDevelopment);
    assert!(local_admins.operations.audit);
    assert!(!local_admins.operations.plan && !local_admins.operations.apply);

    let defender = lookup("v3.defender.ransomware-network-protection")
        .expect("Defender ransomware descriptor");
    assert_eq!(defender.maturity, ImplementationMaturity::InDevelopment);
    assert!(defender.operations.audit && defender.operations.plan);
    assert!(!defender.operations.apply);
}

#[test]
fn non_windows_dispatch_is_typed_unsupported_not_success() {
    let adapter = adapter_for("v3.identity.join").expect("identity adapter");
    let outcome = adapter.execute(
        ExecutionEnvironment::non_windows(),
        CapabilityRequest {
            operation: Operation::Audit,
            parameters: &serde_json::Value::Null,
        },
        None,
    );
    assert_eq!(
        outcome,
        CapabilityOutcome::Unsupported {
            reason: Unsupported::NonWindowsHost
        }
    );
}

#[test]
fn missing_windows_feature_is_typed_unsupported_not_success() {
    let adapter = adapter_for("v3.defender.health").expect("Defender adapter");
    let outcome = adapter.execute(
        ExecutionEnvironment {
            is_windows: true,
            available_requirements: &[],
        },
        CapabilityRequest {
            operation: Operation::Audit,
            parameters: &serde_json::Value::Null,
        },
        None,
    );
    assert_eq!(
        outcome,
        CapabilityOutcome::Unsupported {
            reason: Unsupported::MissingRequirement {
                requirement: "WinDefend service API".to_owned(),
            },
        }
    );
}

#[test]
fn batches_preserve_legacy_audit_membership() {
    assert_eq!(select_batch(Batch::Audit).len(), 46);
    assert_eq!(select_batch(Batch::Remediation).len(), 22);
    assert_eq!(select_batch(Batch::All).len(), 52);
}
