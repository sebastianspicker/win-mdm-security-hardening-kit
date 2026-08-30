use std::{io, path::PathBuf};

use thiserror::Error;

/// Errors returned when an untrusted domain document violates the v3 contract.
#[derive(Debug, Error)]
pub enum DomainError {
    /// The input cannot be read.
    #[error("could not read {path}: {source}")]
    Read {
        /// Path that was read.
        path: PathBuf,
        /// I/O failure.
        #[source]
        source: io::Error,
    },
    /// The input exceeded a configured bound.
    #[error("JSON input exceeds the {limit_name} limit of {limit}")]
    LimitExceeded {
        /// Human-readable bound name.
        limit_name: &'static str,
        /// Maximum permitted value.
        limit: usize,
    },
    /// The input is not well-formed UTF-8.
    #[error("JSON input is not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    /// The JSON syntax or typed schema is invalid.
    #[error("invalid JSON contract: {0}")]
    Json(#[from] serde_json::Error),
    /// A semantic rule was violated after decoding.
    #[error("contract validation failed: {0}")]
    Validation(String),
}

/// Convenience result alias for domain operations.
pub type DomainResult<T> = Result<T, DomainError>;
