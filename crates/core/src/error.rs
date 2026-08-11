//! Error types for the X Chat SDK.

use thiserror::Error;

/// Result type alias for SDK operations.
pub type SdkResult<T> = Result<T, SdkError>;

/// Top-level error type for all SDK operations.
#[derive(Debug, Error)]
pub enum SdkError {
    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// Key management error.
    #[error("Key error: {0}")]
    Key(#[from] KeyError),

    /// Juicebox SDK error.
    #[error("Juicebox error: {0}")]
    Juicebox(#[from] JuiceboxError),

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),

    /// Thrift parsing error.
    #[error("Parse error: {0}")]
    Parse(String),

    /// A required value was neither passed nor available from session state,
    /// or a caller-supplied input violates a send-side rule.
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

/// Errors related to cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Key generation failed.
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Encryption failed.
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed.
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Signature generation failed.
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Signature verification failed.
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid key format or data.
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Invalid input data.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// HKDF operation failed.
    #[error("HKDF failed: {0}")]
    HkdfFailed(String),
}

/// Errors related to key management.
#[derive(Debug, Error)]
pub enum KeyError {
    /// Keys not loaded/unlocked.
    #[error("Keys not unlocked - call unlock() first")]
    NotUnlocked,

    /// Key not found.
    #[error("Key not found: {0}")]
    NotFound(String),

    /// PIN rejected by strength requirements.
    #[error("Weak PIN: {0}")]
    WeakPin(String),

    /// Key reconstruction from bytes failed.
    #[error("Key reconstruction failed: {0}")]
    ReconstructionFailed(String),
}

/// Errors from Juicebox SDK integration.
#[derive(Debug, Error)]
pub enum JuiceboxError {
    /// Wrong PIN provided. `guesses_remaining` is the attempt budget Juicebox
    /// reports after the failure (0 = exhausted, keys locked); `None` when the
    /// count is unavailable. The `guesses_remaining=N` message token is stable
    /// — bindings parse it out of the error string, so the format must not
    /// change (the bare `Invalid PIN` prefix likewise stays as-is).
    #[error("Invalid PIN{}", .guesses_remaining.map(|n| format!(": guesses_remaining={n}")).unwrap_or_default())]
    InvalidPin {
        /// Remaining PIN attempts reported by Juicebox, if known.
        guesses_remaining: Option<u16>,
    },

    /// Keys not registered yet.
    #[error("Keys not registered")]
    NotRegistered,

    /// Auth token invalid.
    #[error("Invalid auth token")]
    InvalidAuth,

    /// SDK version too old.
    #[error("Upgrade required - SDK version too old")]
    UpgradeRequired,

    /// Internal assertion failure.
    #[error("Internal error")]
    Assertion,

    /// Transient network/backend failure.
    #[error("Transient error - retry")]
    Transient,

    /// Too many failed attempts.
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Storage operation failed.
    #[error("Storage failed")]
    StorageFailed,

    /// No Juicebox tokens available.
    #[error("No Juicebox tokens")]
    NoTokens,

    /// Key deletion failed.
    #[error("Delete failed: {0}")]
    DeleteFailed(String),

    /// Generic Juicebox error.
    #[error("Juicebox error: {0}")]
    Other(String),
}

impl JuiceboxError {
    /// Returns true if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            JuiceboxError::InvalidPin { .. }
                | JuiceboxError::NotRegistered
                | JuiceboxError::InvalidAuth
                | JuiceboxError::Transient
                | JuiceboxError::RateLimitExceeded
                | JuiceboxError::StorageFailed
        )
    }
}

/// Errors related to serialization/deserialization.
#[derive(Debug, Error)]
pub enum SerializationError {
    /// JSON serialization failed.
    #[error("JSON error: {0}")]
    Json(String),

    /// Base64 encoding/decoding failed.
    #[error("Base64 error: {0}")]
    Base64(String),

    /// Thrift serialization failed.
    #[error("Thrift error: {0}")]
    Thrift(String),

    /// Invalid data format.
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}

impl From<serde_json::Error> for SerializationError {
    fn from(e: serde_json::Error) -> Self {
        SerializationError::Json(e.to_string())
    }
}

impl From<base64::DecodeError> for SerializationError {
    fn from(e: base64::DecodeError) -> Self {
        SerializationError::Base64(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_error_display() {
        let err = SdkError::Parse("bad data".into());
        assert_eq!(err.to_string(), "Parse error: bad data");
    }

    #[test]
    fn test_sdk_error_from_crypto() {
        let crypto = CryptoError::DecryptionFailed("wrong key".into());
        let sdk: SdkError = crypto.into();
        assert!(matches!(sdk, SdkError::Crypto(_)));
        assert!(sdk.to_string().contains("wrong key"));
    }

    #[test]
    fn test_sdk_error_from_key() {
        let key = KeyError::NotUnlocked;
        let sdk: SdkError = key.into();
        assert!(matches!(sdk, SdkError::Key(_)));
        assert!(sdk.to_string().contains("not unlocked"));
    }

    #[test]
    fn test_sdk_error_from_juicebox() {
        let jb = JuiceboxError::InvalidPin {
            guesses_remaining: None,
        };
        let sdk: SdkError = jb.into();
        assert!(matches!(sdk, SdkError::Juicebox(_)));
    }

    #[test]
    fn test_sdk_error_from_serialization() {
        let ser = SerializationError::Base64("oops".into());
        let sdk: SdkError = ser.into();
        assert!(matches!(sdk, SdkError::Serialization(_)));
    }

    #[test]
    fn test_crypto_error_variants_display() {
        assert!(CryptoError::KeyGenerationFailed("x".into())
            .to_string()
            .contains("x"));
        assert!(CryptoError::EncryptionFailed("y".into())
            .to_string()
            .contains("y"));
        assert!(CryptoError::SigningFailed("z".into())
            .to_string()
            .contains("z"));
        assert!(CryptoError::VerificationFailed("w".into())
            .to_string()
            .contains("w"));
        assert!(CryptoError::InvalidKey("k".into())
            .to_string()
            .contains("k"));
        assert!(CryptoError::InvalidInput("i".into())
            .to_string()
            .contains("i"));
        assert!(CryptoError::HkdfFailed("h".into())
            .to_string()
            .contains("h"));
    }

    #[test]
    fn test_key_error_display() {
        assert!(KeyError::NotUnlocked.to_string().contains("unlock"));
        assert!(KeyError::NotFound("foo".into()).to_string().contains("foo"));
        assert!(KeyError::WeakPin("short".into())
            .to_string()
            .contains("PIN"));
        assert!(KeyError::ReconstructionFailed("bad".into())
            .to_string()
            .contains("bad"));
    }

    #[test]
    fn test_juicebox_error_retryable() {
        assert!(JuiceboxError::InvalidPin {
            guesses_remaining: None
        }
        .is_retryable());
        assert!(JuiceboxError::NotRegistered.is_retryable());
        assert!(JuiceboxError::InvalidAuth.is_retryable());
        assert!(JuiceboxError::Transient.is_retryable());
        assert!(JuiceboxError::RateLimitExceeded.is_retryable());
        assert!(JuiceboxError::StorageFailed.is_retryable());

        assert!(!JuiceboxError::UpgradeRequired.is_retryable());
        assert!(!JuiceboxError::Assertion.is_retryable());
        assert!(!JuiceboxError::NoTokens.is_retryable());
        assert!(!JuiceboxError::Other("x".into()).is_retryable());
    }

    #[test]
    fn test_juicebox_error_display() {
        assert_eq!(
            JuiceboxError::InvalidPin {
                guesses_remaining: None
            }
            .to_string(),
            "Invalid PIN"
        );
        assert_eq!(
            JuiceboxError::InvalidPin {
                guesses_remaining: Some(3)
            }
            .to_string(),
            "Invalid PIN: guesses_remaining=3"
        );
        assert_eq!(
            JuiceboxError::InvalidPin {
                guesses_remaining: Some(0)
            }
            .to_string(),
            "Invalid PIN: guesses_remaining=0"
        );
        assert!(JuiceboxError::NoTokens.to_string().contains("token"));
        assert!(JuiceboxError::Other("custom".into())
            .to_string()
            .contains("custom"));
    }

    #[test]
    fn test_serialization_error_from_serde() {
        let json_err = serde_json::from_str::<String>("not json").unwrap_err();
        let ser_err: SerializationError = json_err.into();
        assert!(matches!(ser_err, SerializationError::Json(_)));
    }

    #[test]
    fn test_serialization_error_from_base64() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let b64_err = STANDARD.decode("!!!invalid!!!").unwrap_err();
        let ser_err: SerializationError = b64_err.into();
        assert!(matches!(ser_err, SerializationError::Base64(_)));
    }

    #[test]
    fn test_serialization_error_display() {
        assert!(SerializationError::Thrift("t".into())
            .to_string()
            .contains("t"));
        assert!(SerializationError::InvalidFormat("f".into())
            .to_string()
            .contains("f"));
    }
}
