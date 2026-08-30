use std::{fmt, str::FromStr};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::DomainResult;

/// Lowercase, 32-byte SHA-256 digest used to bind profiles, plans, and evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd)]
#[schemars(with = "String")]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Wraps the output bytes of an already-completed SHA-256 calculation.
    #[must_use]
    pub const fn from_digest_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Calculates the SHA-256 digest for the supplied bytes.
    #[must_use]
    pub fn of_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the canonical lowercase hexadecimal representation.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write as _;
            let _ = write!(output, "{byte:02x}");
        }
        output
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl FromStr for Sha256Digest {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            || value.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err("SHA-256 digests must be exactly 64 lowercase hexadecimal characters");
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_nibble(pair[0]).ok_or("SHA-256 digest is not hexadecimal")?;
            let low = hex_nibble(pair[1]).ok_or("SHA-256 digest is not hexadecimal")?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Serializes any value to a recursively key-sorted, whitespace-free JSON value.
///
/// # Errors
///
/// Returns an error if `value` cannot be serialized as JSON.
pub fn canonical_json_value<T: Serialize>(value: &T) -> DomainResult<Value> {
    Ok(serde_json::to_value(value)?)
}

/// Serializes any value to a recursively key-sorted, whitespace-free UTF-8 JSON byte sequence.
///
/// # Errors
///
/// Returns an error if `value` cannot be serialized as JSON.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> DomainResult<Vec<u8>> {
    let value = canonical_json_value(value)?;
    let mut output = Vec::new();
    write_canonical_value(&value, &mut output)?;
    Ok(output)
}

/// Calculates SHA-256 over the canonical JSON representation of a value.
///
/// # Errors
///
/// Returns an error if `value` cannot be serialized as JSON.
pub fn canonical_json_digest<T: Serialize>(value: &T) -> DomainResult<Sha256Digest> {
    Ok(Sha256Digest::of_bytes(canonical_json_bytes(value)?))
}

fn write_canonical_value(value: &Value, output: &mut Vec<u8>) -> DomainResult<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => {
            output.extend_from_slice(serde_json::to_string(string)?.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut members = values.iter().collect::<Vec<_>>();
            members.sort_unstable_by_key(|(key, _)| *key);
            for (index, (key, item)) in members.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(serde_json::to_string(key)?.as_bytes());
                output.push(b':');
                write_canonical_value(item, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}
