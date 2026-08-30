//! Typed Windows Firewall logging observation and drift-only planning.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Maximum UTF-8 length accepted for the fixed firewall log path.
pub const MAX_LOG_FILE_PATH_BYTES: usize = 1024;
/// Minimum accepted firewall log size in kibibytes.
pub const MIN_LOG_SIZE_KILOBYTES: u16 = 1;
/// Maximum accepted firewall log size in kibibytes.
pub const MAX_LOG_SIZE_KILOBYTES: u16 = 32_767;

/// One of the three built-in Windows Firewall profiles.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallProfile {
    /// Domain-authenticated networks.
    Domain,
    /// User-designated private networks.
    Private,
    /// Public or unidentified networks.
    Public,
}

/// Typed evidence for one Windows Firewall value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
pub enum FirewallEvidence<T> {
    /// The value was read successfully.
    Present(T),
    /// The value does not exist.
    Missing,
    /// The caller lacks read access.
    AccessDenied,
    /// The provider or property is unavailable.
    Unavailable,
    /// The provider returned an unrecognized value.
    Unparsed,
}

impl<T> FirewallEvidence<T> {
    /// Returns whether the evidence contains a successfully read value.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        matches!(self, Self::Present(_))
    }
}

/// Fixed logging evidence for one built-in firewall profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FirewallProfileObservation {
    /// Whether dropped packets are logged.
    pub log_dropped_packets: FirewallEvidence<bool>,
    /// Whether successful connections are logged.
    pub log_successful_connections: FirewallEvidence<bool>,
    /// Effective firewall log path.
    pub log_file_path: FirewallEvidence<String>,
    /// Effective maximum log size in kibibytes.
    pub log_max_size_kilobytes: FirewallEvidence<u16>,
}

impl FirewallProfileObservation {
    /// Returns whether all four logging values were read successfully.
    #[must_use]
    pub const fn logging_is_complete(&self) -> bool {
        self.log_dropped_packets.is_present()
            && self.log_successful_connections.is_present()
            && self.log_file_path.is_present()
            && self.log_max_size_kilobytes.is_present()
    }
}

/// Whether local Windows Firewall policy may be modified.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallPolicyModifyState {
    /// Local policy is writable.
    LocalPolicyWritable,
    /// Group Policy overrides local settings.
    GroupPolicyOverride,
    /// Local inbound changes are blocked.
    InboundBlocked,
    /// The provider returned an unknown state.
    Unknown,
}

/// Fixed logging and policy-modification observations for all profiles.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FirewallObservation {
    /// Evidence keyed by built-in profile.
    pub profiles: BTreeMap<FirewallProfile, FirewallProfileObservation>,
    /// Effective local-policy modification state.
    pub local_policy_modify_state: FirewallPolicyModifyState,
}

impl FirewallObservation {
    /// Returns whether all profile evidence is complete and local policy is writable.
    #[must_use]
    pub fn logging_is_complete(&self) -> bool {
        self.local_policy_modify_state == FirewallPolicyModifyState::LocalPolicyWritable
            && fixed_profiles().iter().all(|profile| {
                self.profiles
                    .get(profile)
                    .is_some_and(FirewallProfileObservation::logging_is_complete)
            })
    }
}

/// Optional defaults supplied by a bounded configuration catalog.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct FirewallLoggingConfig {
    /// Default dropped-packet logging selection.
    pub log_dropped_packets: Option<bool>,
    /// Default successful-connection logging selection.
    pub log_successful_connections: Option<bool>,
    /// Default bounded firewall log path.
    pub log_file_path: Option<String>,
    /// Default maximum log size in kibibytes.
    pub log_max_size_kilobytes: Option<u16>,
}

/// Strict request parameters with explicit values overriding catalog defaults.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct FirewallLoggingParameters {
    /// Optional bounded configuration-catalog defaults.
    pub config: Option<FirewallLoggingConfig>,
    /// Explicit dropped-packet logging selection.
    pub log_dropped_packets: Option<bool>,
    /// Explicit successful-connection logging selection.
    pub log_successful_connections: Option<bool>,
    /// Explicit bounded firewall log path.
    pub log_file_path: Option<String>,
    /// Explicit maximum log size in kibibytes.
    pub log_max_size_kilobytes: Option<u16>,
}

/// Fully resolved firewall logging desired state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FirewallLoggingDesiredState {
    /// Whether dropped packets should be logged.
    pub log_dropped_packets: bool,
    /// Whether successful connections should be logged.
    pub log_successful_connections: bool,
    /// Desired bounded firewall log path.
    pub log_file_path: String,
    /// Desired maximum log size in kibibytes.
    pub log_max_size_kilobytes: u16,
}

/// One fixed firewall logging field that can drift.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallLoggingField {
    /// Dropped-packet logging.
    LogDroppedPackets,
    /// Successful-connection logging.
    LogSuccessfulConnections,
    /// Firewall log path.
    LogFilePath,
    /// Maximum firewall log size.
    LogMaxSizeKilobytes,
}

/// Fixed logging fields that differ for one profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FirewallLoggingDrift {
    /// Built-in profile containing drift.
    pub profile: FirewallProfile,
    /// Fixed fields whose observed and desired values differ.
    pub fields: Vec<FirewallLoggingField>,
}

/// Non-mutating firewall logging proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FirewallLoggingPlan {
    /// Complete observation used to derive the proposal.
    pub observation: FirewallObservation,
    /// Validated desired state.
    pub desired: FirewallLoggingDesiredState,
    /// Differences grouped by built-in profile.
    pub drift: Vec<FirewallLoggingDrift>,
    /// Whether future mutation would require Administrator authority.
    pub requires_administrator: bool,
    /// Whether this foundation exposes an Apply operation.
    pub apply_supported: bool,
    /// Declared exclusions that prevent a parity claim.
    pub exclusions: Vec<&'static str>,
}

/// Resolves strict finite configuration and fixed defaults.
///
/// # Errors
///
/// Returns an error for an invalid path or log-size bound.
pub fn resolve_firewall_logging_desired_state(
    parameters: &FirewallLoggingParameters,
) -> Result<FirewallLoggingDesiredState, String> {
    let config = parameters.config.as_ref();
    let log_file_path = choose_string(
        parameters.log_file_path.as_ref(),
        config.and_then(|value| value.log_file_path.as_ref()),
        r"%systemroot%\system32\LogFiles\Firewall\pfirewall.log",
    );
    if log_file_path.trim().is_empty()
        || log_file_path.len() > MAX_LOG_FILE_PATH_BYTES
        || log_file_path.contains('\0')
    {
        return Err("log_file_path must be a bounded non-empty Windows path".into());
    }
    let log_max_size_kilobytes = parameters
        .log_max_size_kilobytes
        .or(config.and_then(|value| value.log_max_size_kilobytes))
        .unwrap_or(20_480);
    if !(MIN_LOG_SIZE_KILOBYTES..=MAX_LOG_SIZE_KILOBYTES).contains(&log_max_size_kilobytes) {
        return Err(format!(
            "log_max_size_kilobytes must be between {MIN_LOG_SIZE_KILOBYTES} and {MAX_LOG_SIZE_KILOBYTES}"
        ));
    }
    Ok(FirewallLoggingDesiredState {
        log_dropped_packets: parameters
            .log_dropped_packets
            .or(config.and_then(|value| value.log_dropped_packets))
            .unwrap_or(true),
        log_successful_connections: parameters
            .log_successful_connections
            .or(config.and_then(|value| value.log_successful_connections))
            .unwrap_or(false),
        log_file_path,
        log_max_size_kilobytes,
    })
}

/// Compares fixed profiles; incomplete or overridden evidence is rejected.
///
/// # Errors
///
/// Returns an error when any evidence is incomplete or locally overridden.
pub fn build_firewall_logging_plan(
    observation: FirewallObservation,
    desired: FirewallLoggingDesiredState,
) -> Result<FirewallLoggingPlan, String> {
    if !observation.logging_is_complete() {
        return Err("firewall logging evidence is incomplete or locally overridden".into());
    }
    let drift = fixed_profiles()
        .iter()
        .filter_map(|profile| {
            let current = observation.profiles.get(profile)?;
            let mut fields = Vec::new();
            if !matches!(current.log_dropped_packets, FirewallEvidence::Present(value) if value == desired.log_dropped_packets) {
                fields.push(FirewallLoggingField::LogDroppedPackets);
            }
            if !matches!(current.log_successful_connections, FirewallEvidence::Present(value) if value == desired.log_successful_connections) {
                fields.push(FirewallLoggingField::LogSuccessfulConnections);
            }
            if !matches!(current.log_file_path, FirewallEvidence::Present(ref value) if value == &desired.log_file_path) {
                fields.push(FirewallLoggingField::LogFilePath);
            }
            if !matches!(current.log_max_size_kilobytes, FirewallEvidence::Present(value) if value == desired.log_max_size_kilobytes) {
                fields.push(FirewallLoggingField::LogMaxSizeKilobytes);
            }
            (!fields.is_empty()).then_some(FirewallLoggingDrift {
                profile: *profile,
                fields,
            })
        })
        .collect();
    Ok(FirewallLoggingPlan {
        observation,
        desired,
        drift,
        requires_administrator: true,
        apply_supported: false,
        exclusions: vec![
            "firewall rule enumeration and mutation",
            "all mutation and worker actions",
            "Windows VM validation",
            "legacy-script semantic oracle",
        ],
    })
}

/// Returns the only Windows Firewall profiles accepted by the policy.
#[must_use]
pub const fn fixed_profiles() -> [FirewallProfile; 3] {
    [
        FirewallProfile::Domain,
        FirewallProfile::Private,
        FirewallProfile::Public,
    ]
}

fn choose_string(primary: Option<&String>, fallback: Option<&String>, default: &str) -> String {
    primary
        .or(fallback)
        .cloned()
        .unwrap_or_else(|| default.to_owned())
}
