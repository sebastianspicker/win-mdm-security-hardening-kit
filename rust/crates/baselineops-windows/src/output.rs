use crate::PlatformError;

/// Explicit encoding selected by a capability-specific native-tool adapter.
#[derive(Clone, Copy, Debug)]
pub enum NativeEncoding {
    /// Strict UTF-8.
    Utf8,
    /// Little-endian UTF-16 without relying on the process locale.
    Utf16Le,
}

/// Decode already bounded native output without lossy replacement.
///
/// # Errors
///
/// Returns an error when the bytes are not valid in the explicitly selected
/// encoding.
pub fn decode_native_output(
    bytes: &[u8],
    encoding: NativeEncoding,
) -> Result<String, PlatformError> {
    match encoding {
        NativeEncoding::Utf8 => {
            std::str::from_utf8(bytes)
                .map(str::to_owned)
                .map_err(|_| PlatformError::InvalidUtf8 {
                    path: "<native-output>".into(),
                })
        }
        NativeEncoding::Utf16Le => {
            if !bytes.len().is_multiple_of(2) {
                return Err(PlatformError::TrustFailure(
                    "UTF-16 native output has an odd byte length".into(),
                ));
            }
            let words = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            String::from_utf16(&words)
                .map_err(|error| PlatformError::TrustFailure(format!("invalid UTF-16: {error}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding_is_strict_and_explicit() {
        assert_eq!(
            decode_native_output(b"ok", NativeEncoding::Utf8).expect("UTF-8"),
            "ok"
        );
        assert_eq!(
            decode_native_output(&[b'o', 0, b'k', 0], NativeEncoding::Utf16Le).expect("UTF-16"),
            "ok"
        );
        assert!(decode_native_output(&[0xff], NativeEncoding::Utf8).is_err());
        assert!(decode_native_output(&[0], NativeEncoding::Utf16Le).is_err());
    }
}
