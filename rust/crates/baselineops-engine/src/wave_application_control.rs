//! Read-only native execution for AMSI and `AppLocker` audits.

use baselineops_capabilities::{
    AmsiPolicy, AppLockerPolicy, CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome,
    CapabilityRequest, ClientBaselinePolicy, DriverIntegrityPolicy, ExploitProtectionPolicy,
    Operation, evaluate_amsi, evaluate_applocker, evaluate_client_baseline,
    evaluate_driver_integrity, evaluate_exploit_protection,
};
use baselineops_windows::{
    PlatformError, audit_amsi, audit_applocker, audit_client_baseline, audit_driver_integrity,
    audit_exploit_protection,
};
use serde::de::DeserializeOwned;

/// Native audit executor for capabilities 50 and 51.
pub struct WaveApplicationControlWindowsExecutor;

impl CapabilityExecutor for WaveApplicationControlWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        let result = match (descriptor.id, request.operation) {
            ("v3.amsi.audit", Operation::Audit) => amsi(request),
            ("v3.applocker.audit", Operation::Audit) => applocker(request),
            ("v3.driver-signing.integrity", Operation::Audit) => driver_integrity(request),
            ("v3.client-security-baseline", Operation::Audit) => client_baseline(request),
            ("v3.exploit-protection.audit", Operation::Audit) => exploit_protection(request),
            (
                "v3.amsi.audit"
                | "v3.applocker.audit"
                | "v3.driver-signing.integrity"
                | "v3.client-security-baseline"
                | "v3.exploit-protection.audit",
                _,
            ) => Err(PlatformError::TrustFailure(
                "application-control and integrity audits are read-only".into(),
            )),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the application-control executor".into(),
            )),
        };
        result.map_or_else(
            |error| CapabilityOutcome::Failed {
                capability_id: descriptor.id.into(),
                message: error.to_string(),
            },
            |result| CapabilityOutcome::Completed { result },
        )
    }
}

fn amsi(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: AmsiPolicy = parameters(request.parameters, "AMSI")?;
    json(evaluate_amsi(audit_amsi()?, &policy))
}

fn applocker(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: AppLockerPolicy = parameters(request.parameters, "AppLocker")?;
    json(evaluate_applocker(audit_applocker()?, &policy))
}

fn driver_integrity(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: DriverIntegrityPolicy = parameters(request.parameters, "driver integrity")?;
    json(evaluate_driver_integrity(
        audit_driver_integrity()?,
        &policy,
    ))
}

fn client_baseline(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: ClientBaselinePolicy = parameters(request.parameters, "client baseline")?;
    json(evaluate_client_baseline(audit_client_baseline()?, &policy))
}

fn exploit_protection(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: ExploitProtectionPolicy = parameters(request.parameters, "exploit protection")?;
    json(evaluate_exploit_protection(
        audit_exploit_protection()?,
        &policy,
    ))
}

fn parameters<T: DeserializeOwned>(
    value: &serde_json::Value,
    label: &str,
) -> Result<T, PlatformError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!("invalid {label} audit parameters: {error}"))
    })
}

fn json(value: impl serde::Serialize) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| PlatformError::TrustFailure(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_capabilities::lookup;

    #[test]
    fn rejects_unknown_parameters_and_mutation_before_platform_access() {
        for (id, parameters) in [
            ("v3.amsi.audit", serde_json::json!({"path":"HKLM"})),
            (
                "v3.applocker.audit",
                serde_json::json!({"collection":"Exe"}),
            ),
            (
                "v3.driver-signing.integrity",
                serde_json::json!({"identifier":"{default}"}),
            ),
            (
                "v3.client-security-baseline",
                serde_json::json!({"reference":"file.json"}),
            ),
            (
                "v3.exploit-protection.audit",
                serde_json::json!({"process":"browser.exe"}),
            ),
        ] {
            let descriptor = lookup(id).expect("descriptor");
            assert!(matches!(
                WaveApplicationControlWindowsExecutor.execute(
                    descriptor,
                    CapabilityRequest {
                        operation: Operation::Audit,
                        parameters: &parameters,
                    }
                ),
                CapabilityOutcome::Failed { .. }
            ));
            assert!(matches!(
                WaveApplicationControlWindowsExecutor.execute(
                    descriptor,
                    CapabilityRequest {
                        operation: Operation::Apply,
                        parameters: &serde_json::json!({}),
                    }
                ),
                CapabilityOutcome::Failed { .. }
            ));
        }
    }
}
