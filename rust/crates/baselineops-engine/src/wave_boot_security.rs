//! Shared Audit/Plan executor for capabilities 13, 39, and 40.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    CredentialGuardPolicy, LsaProtectionPolicy, LsassHardeningPolicy, Operation,
    evaluate_credential_guard, evaluate_lsa_protection, evaluate_lsass_hardening,
    validate_credential_guard, validate_lsa_protection,
};
use baselineops_windows::{PlatformError, audit_boot_security};
use serde::de::DeserializeOwned;

/// Native shared executor for bounded boot-security policy foundations.
pub struct WaveBootSecurityWindowsExecutor;

impl CapabilityExecutor for WaveBootSecurityWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if !matches!(request.operation, Operation::Audit | Operation::Plan) {
            return failed(descriptor, "boot-security mutation is not available");
        }
        let result = match descriptor.id {
            "v3.lsass.vbs-hardening" => lsass(request),
            "v3.credential-guard.vbs" => credential_guard(request),
            "v3.lsa.protection" => lsa(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the boot-security executor".into(),
            )),
        };
        result.map_or_else(
            |error| failed(descriptor, &error.to_string()),
            |result| CapabilityOutcome::Completed { result },
        )
    }
}

fn lsass(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: LsassHardeningPolicy = parameters(request.parameters)?;
    json(evaluate_lsass_hardening(audit_boot_security()?, &policy))
}

fn credential_guard(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: CredentialGuardPolicy = parameters(request.parameters)?;
    validate_credential_guard(&policy).map_err(invalid)?;
    json(evaluate_credential_guard(audit_boot_security()?, &policy))
}

fn lsa(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: LsaProtectionPolicy = parameters(request.parameters)?;
    validate_lsa_protection(&policy).map_err(invalid)?;
    json(evaluate_lsa_protection(audit_boot_security()?, &policy))
}

fn parameters<T: DeserializeOwned>(value: &serde_json::Value) -> Result<T, PlatformError> {
    serde_json::from_value(value.clone()).map_err(|error| invalid(&error.to_string()))
}

fn json(value: impl serde::Serialize) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| PlatformError::TrustFailure(error.to_string()))
}

fn invalid(message: &str) -> PlatformError {
    PlatformError::TrustFailure(format!("invalid boot-security parameters: {message}"))
}

fn failed(descriptor: &'static CapabilityDescriptor, message: &str) -> CapabilityOutcome {
    CapabilityOutcome::Failed {
        capability_id: descriptor.id.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_capabilities::lookup;

    #[test]
    fn unknown_values_and_apply_reject_before_platform_access() {
        for (id, parameters) in [
            ("v3.lsass.vbs-hardening", serde_json::json!({"path":"x"})),
            (
                "v3.credential-guard.vbs",
                serde_json::json!({"platform_security":2}),
            ),
            (
                "v3.lsa.protection",
                serde_json::json!({"target_run_as_ppl":3}),
            ),
        ] {
            let descriptor = lookup(id).expect("descriptor");
            assert!(matches!(
                WaveBootSecurityWindowsExecutor.execute(
                    descriptor,
                    CapabilityRequest {
                        operation: Operation::Audit,
                        parameters: &parameters,
                    }
                ),
                CapabilityOutcome::Failed { .. }
            ));
            assert!(matches!(
                WaveBootSecurityWindowsExecutor.execute(
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
