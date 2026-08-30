//! Read-only native executor for capability 18's fixed firewall profile subset.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    FirewallBaselineParameters, Operation, Unsupported, build_firewall_baseline_plan,
    evaluate_firewall_baseline,
};
use baselineops_windows::{PlatformError, observe_firewall_baseline};

/// Native capability 18 executor for fixed profiles only.
///
/// It cannot apply a plan: rules, policy stores, rollback, logging, and service
/// control remain outside this executor's authority.
pub struct WaveFirewallBaselineWindowsExecutor;

impl CapabilityExecutor for WaveFirewallBaselineWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if descriptor.id == "v3.firewall.baseline" && request.operation == Operation::Apply {
            return CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply,
                },
            };
        }
        let result = match (descriptor.id, request.operation) {
            ("v3.firewall.baseline", Operation::Audit) => audit(request),
            ("v3.firewall.baseline", Operation::Plan) => plan(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the firewall baseline executor".into(),
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

fn parameters(value: &serde_json::Value) -> Result<FirewallBaselineParameters, PlatformError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!("invalid firewall baseline parameters: {error}"))
    })
}

fn audit(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let parameters = parameters(request.parameters)?;
    json(evaluate_firewall_baseline(
        observe_firewall_baseline()?,
        &parameters,
    ))
}

fn plan(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let parameters = parameters(request.parameters)?;
    json(
        build_firewall_baseline_plan(observe_firewall_baseline()?, &parameters)
            .map_err(PlatformError::TrustFailure)?,
    )
}

fn json(value: impl serde::Serialize) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| {
        PlatformError::TrustFailure(format!("firewall baseline serialization failed: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_capabilities::lookup;

    #[test]
    fn legacy_dynamic_parameters_reject_before_windows_access() {
        let descriptor = lookup("v3.firewall.baseline").expect("descriptor");
        for parameters in [
            serde_json::json!({"catalog_path":"untrusted.json"}),
            serde_json::json!({"profiles":{"domain":{"rule_name":"anything"}}}),
        ] {
            assert!(matches!(
                WaveFirewallBaselineWindowsExecutor.execute(
                    descriptor,
                    CapabilityRequest {
                        operation: Operation::Audit,
                        parameters: &parameters,
                    },
                ),
                CapabilityOutcome::Failed { .. }
            ));
        }
    }

    #[test]
    fn raw_apply_is_typed_unsupported_before_windows_access() {
        let descriptor = lookup("v3.firewall.baseline").expect("descriptor");
        assert!(matches!(
            WaveFirewallBaselineWindowsExecutor.execute(
                descriptor,
                CapabilityRequest {
                    operation: Operation::Apply,
                    parameters: &serde_json::json!({}),
                },
            ),
            CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply
                }
            }
        ));
    }
}
