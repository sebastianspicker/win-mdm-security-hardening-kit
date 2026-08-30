//! Bounded, versioned framing for the local elevated-worker broker.
//!
//! The types in this module are intentionally transport-neutral so parser and
//! replay handling receive portable test coverage. Windows named-pipe plumbing
//! is an optional adapter over the same exact frames.

use crate::PlatformError;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

#[cfg(windows)]
mod auth;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use auth::{ProcessTokenIdentity, inspect_process};
#[cfg(windows)]
pub use windows::{NamedPipeClient, NamedPipeServer, PipePeerVerifier};

/// Largest allowed encoded broker frame, excluding its four-byte length field.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Only protocol revision understood by this boundary slice.
pub const PROTOCOL_VERSION: u16 = 1;
const MAX_NONCE_BYTES: usize = 96;
const MAX_KIND_BYTES: usize = 64;
const MAX_SESSION_BYTES: usize = 64;
const MAX_PLAN_ID_BYTES: usize = 128;
const SHA256_HEX_BYTES: usize = 64;

/// Values that bind every broker message to one reviewed plan exchange.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerBinding {
    /// Session token passed directly from the CLI to the elevated worker.
    pub session_id: String,
    /// Stable identifier of the reviewed plan.
    pub plan_id: String,
    /// Canonical SHA-256 digest of the exact plan relevant to this message.
    pub plan_digest: String,
    /// Nonce of the message to which this message is replying, if any.
    pub reply_to: Option<String>,
}

impl BrokerBinding {
    /// Validate the stable exchange binding independently of the payload schema.
    ///
    /// # Errors
    ///
    /// Returns an error when a session, plan, digest, or reply nonce is invalid.
    pub fn validate(&self) -> Result<(), PlatformError> {
        if self.session_id.is_empty()
            || self.session_id.len() > MAX_SESSION_BYTES
            || !self
                .session_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(PlatformError::ProtocolRejected(
                "session identifier is invalid".into(),
            ));
        }
        if self.plan_id.is_empty()
            || self.plan_id.len() > MAX_PLAN_ID_BYTES
            || !self
                .plan_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(PlatformError::ProtocolRejected(
                "plan identifier is invalid".into(),
            ));
        }
        if !valid_hex(&self.plan_digest, SHA256_HEX_BYTES) {
            return Err(PlatformError::ProtocolRejected(
                "plan digest is not SHA-256 hex".into(),
            ));
        }
        if self
            .reply_to
            .as_deref()
            .is_some_and(|nonce| !valid_nonce(nonce))
        {
            return Err(PlatformError::ProtocolRejected(
                "reply nonce is invalid".into(),
            ));
        }
        Ok(())
    }

    /// Reject a reply that is not tied to the expected exchange state.
    ///
    /// # Errors
    ///
    /// Returns an error when any supplied binding differs from the active exchange.
    pub fn require_reply_to(
        &self,
        session_id: &str,
        plan_id: &str,
        plan_digest: &str,
        request_nonce: &str,
    ) -> Result<(), PlatformError> {
        self.validate()?;
        if self.session_id != session_id
            || self.plan_id != plan_id
            || self.plan_digest != plan_digest
            || self.reply_to.as_deref() != Some(request_nonce)
        {
            return Err(PlatformError::ProtocolRejected(
                "reply binding does not match the active exchange".into(),
            ));
        }
        Ok(())
    }

    /// Reject an initiating request that is not bound to the expected plan/session.
    ///
    /// # Errors
    ///
    /// Returns an error when the request has a reply nonce or differs from the active exchange.
    pub fn require_request(
        &self,
        session_id: &str,
        plan_id: &str,
        plan_digest: &str,
    ) -> Result<(), PlatformError> {
        self.validate()?;
        if self.session_id != session_id
            || self.plan_id != plan_id
            || self.plan_digest != plan_digest
            || self.reply_to.is_some()
        {
            return Err(PlatformError::ProtocolRejected(
                "request binding does not match the active exchange".into(),
            ));
        }
        Ok(())
    }
}

/// Versioned broker envelope carried inside a bounded frame.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerMessage {
    /// Fixed protocol revision; peers with another revision are rejected.
    pub version: u16,
    /// Immutable plan/session binding for this message.
    pub binding: BrokerBinding,
    /// Cryptographically random, single-use request nonce encoded as lowercase hex.
    pub nonce: String,
    /// Bounded operation discriminator selected by the trusted client.
    pub kind: String,
    /// Capability-specific canonical JSON payload.
    pub payload: serde_json::Value,
}

impl BrokerMessage {
    /// Validate envelope fields independently of the payload schema.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported versions, unbounded strings, malformed
    /// nonce text, or a non-object payload.
    pub fn validate(&self) -> Result<(), PlatformError> {
        if self.version != PROTOCOL_VERSION {
            return Err(PlatformError::ProtocolRejected(
                "unsupported protocol version".into(),
            ));
        }
        if !valid_nonce(&self.nonce) {
            return Err(PlatformError::ProtocolRejected(
                "nonce is not bounded hexadecimal".into(),
            ));
        }
        if self.kind.is_empty()
            || self.kind.len() > MAX_KIND_BYTES
            || !self
                .kind
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(PlatformError::ProtocolRejected(
                "operation kind is invalid".into(),
            ));
        }
        if !self.payload.is_object() {
            return Err(PlatformError::ProtocolRejected(
                "payload must be a JSON object".into(),
            ));
        }
        self.binding.validate()?;
        Ok(())
    }
}

fn valid_nonce(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NONCE_BYTES
        && value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Exact wire bytes for a broker frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerFrame(pub Vec<u8>);

/// Four-byte big-endian length framing with explicit JSON limits.
pub struct FrameCodec;

impl FrameCodec {
    /// Encode one serializable value as a bounded length-prefixed frame.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails or the encoded value is too large.
    pub fn encode<T: Serialize>(value: &T) -> Result<BrokerFrame, PlatformError> {
        let body = serde_json::to_vec(value).map_err(|error| {
            PlatformError::ProtocolRejected(format!("JSON encode failed: {error}"))
        })?;
        if body.len() > MAX_FRAME_BYTES {
            return Err(PlatformError::ProtocolRejected(
                "frame exceeds maximum size".into(),
            ));
        }
        let length = u32::try_from(body.len())
            .map_err(|_| PlatformError::ProtocolRejected("frame length overflow".into()))?;
        let mut frame = Vec::with_capacity(body.len().saturating_add(4));
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&body);
        Ok(BrokerFrame(frame))
    }

    /// Decode exactly one length-prefixed frame and reject trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid prefix, oversized frame, JSON error, or
    /// trailing bytes that could desynchronize a stream.
    pub fn decode<T: DeserializeOwned>(frame: &[u8]) -> Result<T, PlatformError> {
        if frame.len() < 4 {
            return Err(PlatformError::ProtocolRejected(
                "frame is missing a length prefix".into(),
            ));
        }
        let length_bytes: [u8; 4] = frame[..4]
            .try_into()
            .map_err(|_| PlatformError::ProtocolRejected("frame prefix is invalid".into()))?;
        let expected = u32::from_be_bytes(length_bytes);
        let expected = usize::try_from(expected)
            .map_err(|_| PlatformError::ProtocolRejected("frame length is invalid".into()))?;
        if expected > MAX_FRAME_BYTES || frame.len() != expected.saturating_add(4) {
            return Err(PlatformError::ProtocolRejected(
                "frame length does not match bytes".into(),
            ));
        }
        serde_json::from_slice(&frame[4..]).map_err(|error| {
            PlatformError::ProtocolRejected(format!("JSON decode failed: {error}"))
        })
    }
}

/// Authenticated peer facts supplied by the Windows named-pipe adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    /// OS-assigned client process identifier.
    pub process_id: u32,
    /// Logon session ID bound to the interactive caller.
    pub session_id: u32,
    /// Canonical caller SID string.
    pub user_sid: String,
    /// Token integrity RID; lower values are rejected by a policy hook.
    pub integrity_rid: u32,
    /// Canonical image path resolved from an opened process handle.
    pub image_path: String,
}

/// Fixed-capacity replay detector for accepted client nonces.
#[derive(Debug)]
pub struct ReplayNonceCache {
    ttl: Duration,
    capacity: usize,
    seen: BTreeMap<String, Instant>,
    order: VecDeque<String>,
}

impl ReplayNonceCache {
    /// Create a replay cache with a positive expiry window and capacity.
    ///
    /// # Errors
    ///
    /// Returns an error when either bound is zero.
    pub fn new(ttl: Duration, capacity: usize) -> Result<Self, PlatformError> {
        if ttl.is_zero() || capacity == 0 {
            return Err(PlatformError::ProtocolRejected(
                "replay cache requires positive bounds".into(),
            ));
        }
        Ok(Self {
            ttl,
            capacity,
            seen: BTreeMap::new(),
            order: VecDeque::new(),
        })
    }

    /// Record a validated nonce exactly once within the configured replay window.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::ReplayDetected`] for a live duplicate nonce.
    pub fn accept(&mut self, nonce: &str, now: Instant) -> Result<(), PlatformError> {
        if !valid_nonce(nonce) {
            return Err(PlatformError::ProtocolRejected(
                "nonce is not bounded hexadecimal".into(),
            ));
        }
        self.evict_expired(now);
        if self.seen.contains_key(nonce) {
            return Err(PlatformError::ReplayDetected);
        }
        while self.order.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        let nonce = nonce.to_owned();
        self.seen.insert(nonce.clone(), now);
        self.order.push_back(nonce);
        Ok(())
    }

    fn evict_expired(&mut self, now: Instant) {
        while let Some(nonce) = self.order.front() {
            let Some(accepted_at) = self.seen.get(nonce) else {
                self.order.pop_front();
                continue;
            };
            if now.saturating_duration_since(*accepted_at) < self.ttl {
                break;
            }
            let nonce = self.order.pop_front().expect("front exists");
            self.seen.remove(&nonce);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> BrokerMessage {
        BrokerMessage {
            version: PROTOCOL_VERSION,
            binding: BrokerBinding {
                session_id: "a1b2".into(),
                plan_id: "plan-1".into(),
                plan_digest: "ab".repeat(32),
                reply_to: None,
            },
            nonce: "a1b2".into(),
            kind: "plan.apply".into(),
            payload: serde_json::json!({"id": "x"}),
        }
    }

    #[test]
    fn frame_round_trip_is_exact() {
        let frame = FrameCodec::encode(&message()).expect("encode");
        assert_eq!(
            FrameCodec::decode::<BrokerMessage>(&frame.0).expect("decode"),
            message()
        );
    }

    #[test]
    fn malformed_lengths_and_unknown_fields_fail_closed() {
        assert!(FrameCodec::decode::<BrokerMessage>(&[0, 0, 0, 3, b'{', b'}']).is_err());
        let frame = FrameCodec::encode(
            &serde_json::json!({"version":1,"binding":{"sessionId":"a1","planId":"p","planDigest":"abababababababababababababababababababababababababababababababab","replyTo":null},"nonce":"a1","kind":"x","payload":{},"extra":true}),
        )
        .expect("frame");
        assert!(FrameCodec::decode::<BrokerMessage>(&frame.0).is_err());
    }

    #[test]
    fn envelope_and_replay_bounds_are_enforced() {
        let mut invalid = message();
        invalid.nonce = "not hex".into();
        assert!(invalid.validate().is_err());
        let now = Instant::now();
        let mut cache = ReplayNonceCache::new(Duration::from_secs(1), 1).expect("cache");
        cache.accept("a1", now).expect("first use");
        assert!(matches!(
            cache.accept("a1", now),
            Err(PlatformError::ReplayDetected)
        ));
        cache.accept("b2", now).expect("capacity evicts old value");
        cache.accept("a1", now).expect("evicted nonce is accepted");
    }

    #[test]
    fn reply_binding_cannot_cross_sessions_plans_or_nonces() {
        let request = message();
        let mut reply = message();
        reply.binding.reply_to = Some(request.nonce.clone());
        reply.binding.plan_digest = "cd".repeat(32);
        assert!(
            reply
                .binding
                .require_reply_to("a1b2", "plan-1", &"cd".repeat(32), &request.nonce)
                .is_ok()
        );
        reply.binding.reply_to = Some("ffff".into());
        assert!(
            reply
                .binding
                .require_reply_to("a1b2", "plan-1", &"cd".repeat(32), &request.nonce)
                .is_err()
        );
    }
}
