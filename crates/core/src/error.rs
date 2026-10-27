//! Error types for the X Chat SDK.

use thiserror::Error;

/// Result type alias for SDK operations.
pub type SdkResult<T> = Result<T, SdkError>;

/// Top-level error type for all SDK operations.
#[derive(Debug, Error)]
#[non_exhaustive]
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

    /// A required value was neither passed nor available from session state.
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// A caller-supplied parameter is missing or invalid. The message names
    /// it and says what to pass instead.
    #[error("{0}")]
    InvalidInput(String),
}

/// What kind of failure an [`SdkError`] is. Every binding reports the same
/// kind for the same failure: Python as the exception class, Go, JS, .NET
/// and the JVM as the error's kind, and the C ABI as the `kind` of its error
/// document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A parameter is missing or invalid; the message names it.
    InvalidInput,
    /// A value was neither passed nor available from the chat's state: no
    /// keys loaded, no session identity, no cached conversation key.
    InvalidState,
    /// Event or other wire data is malformed.
    Parse,
    /// Ciphertext did not decrypt, or no key for it was available.
    Decryption,
    /// A signature did not verify, or could not be verified while unverified
    /// events are rejected.
    Verification,
    /// Juicebox rejected the PIN; [`SdkError::guesses_remaining`] holds the
    /// attempts left when Juicebox reports them.
    InvalidPin,
    /// Another Juicebox key-storage failure.
    Juicebox,
    /// A failure inside the SDK, such as a cryptographic primitive failing.
    Internal,
}

impl ErrorKind {
    /// The kind's name as the C ABI and the bindings carry it, in
    /// snake_case: `invalid_input`, `invalid_state`, `parse`, `decryption`,
    /// `verification`, `invalid_pin`, `juicebox` or `internal`.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::InvalidInput => "invalid_input",
            ErrorKind::InvalidState => "invalid_state",
            ErrorKind::Parse => "parse",
            ErrorKind::Decryption => "decryption",
            ErrorKind::Verification => "verification",
            ErrorKind::InvalidPin => "invalid_pin",
            ErrorKind::Juicebox => "juicebox",
            ErrorKind::Internal => "internal",
        }
    }
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl SdkError {
    /// What kind of failure this is.
    pub fn kind(&self) -> ErrorKind {
        match self {
            SdkError::InvalidInput(_) => ErrorKind::InvalidInput,
            SdkError::InvalidState(_) => ErrorKind::InvalidState,
            SdkError::Parse(_) | SdkError::Serialization(_) => ErrorKind::Parse,
            SdkError::Crypto(e) => match e {
                CryptoError::DecryptionFailed(_) => ErrorKind::Decryption,
                CryptoError::VerificationFailed(_) => ErrorKind::Verification,
                CryptoError::InvalidKey(_) | CryptoError::InvalidInput(_) => {
                    ErrorKind::InvalidInput
                }
                _ => ErrorKind::Internal,
            },
            SdkError::Key(e) => match e {
                KeyError::NotUnlocked | KeyError::NotFound(_) => ErrorKind::InvalidState,
                KeyError::WeakPin(_) => ErrorKind::InvalidInput,
                KeyError::ReconstructionFailed(_) => ErrorKind::Juicebox,
            },
            SdkError::Juicebox(JuiceboxError::InvalidPin { .. }) => ErrorKind::InvalidPin,
            SdkError::Juicebox(_) => ErrorKind::Juicebox,
        }
    }

    /// The PIN attempts left after an invalid-PIN failure, when Juicebox
    /// reports them: `0` means the guess budget is exhausted and the stored
    /// keys are locked. `None` for every other failure.
    pub fn guesses_remaining(&self) -> Option<u16> {
        match self {
            SdkError::Juicebox(JuiceboxError::InvalidPin { guesses_remaining }) => {
                *guesses_remaining
            }
            _ => None,
        }
    }
}

/// Errors related to cryptographic operations.
#[derive(Debug, Error)]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
pub enum JuiceboxError {
    /// Wrong PIN provided. `guesses_remaining` is the attempt budget Juicebox
    /// reports after the failure (0 = exhausted, keys locked); `None` when the
    /// count is unavailable. Read it with [`SdkError::guesses_remaining`].
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
        match self {
            // A zero remaining budget means the stored keys are locked;
            // another attempt cannot succeed.
            JuiceboxError::InvalidPin { guesses_remaining } => *guesses_remaining != Some(0),
            JuiceboxError::NotRegistered
            | JuiceboxError::InvalidAuth
            | JuiceboxError::Transient
            | JuiceboxError::RateLimitExceeded
            | JuiceboxError::StorageFailed => true,
            _ => false,
        }
    }
}

/// Errors related to serialization/deserialization.
#[derive(Debug, Error)]
#[non_exhaustive]
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
        assert!(JuiceboxError::InvalidPin {
            guesses_remaining: Some(1)
        }
        .is_retryable());
        // An exhausted guess budget locks the stored keys; retrying a PIN
        // cannot succeed.
        assert!(!JuiceboxError::InvalidPin {
            guesses_remaining: Some(0)
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
    fn every_error_has_a_kind() {
        let cases = [
            (SdkError::InvalidInput("x".into()), ErrorKind::InvalidInput),
            (SdkError::InvalidState("x".into()), ErrorKind::InvalidState),
            (SdkError::Parse("x".into()), ErrorKind::Parse),
            (
                SerializationError::Base64("x".into()).into(),
                ErrorKind::Parse,
            ),
            (
                CryptoError::DecryptionFailed("x".into()).into(),
                ErrorKind::Decryption,
            ),
            (
                CryptoError::VerificationFailed("x".into()).into(),
                ErrorKind::Verification,
            ),
            (
                CryptoError::InvalidKey("x".into()).into(),
                ErrorKind::InvalidInput,
            ),
            (
                CryptoError::SigningFailed("x".into()).into(),
                ErrorKind::Internal,
            ),
            (KeyError::NotUnlocked.into(), ErrorKind::InvalidState),
            (
                KeyError::WeakPin("x".into()).into(),
                ErrorKind::InvalidInput,
            ),
            (
                JuiceboxError::InvalidPin {
                    guesses_remaining: Some(2),
                }
                .into(),
                ErrorKind::InvalidPin,
            ),
            (JuiceboxError::NotRegistered.into(), ErrorKind::Juicebox),
        ];
        for (error, kind) in cases {
            assert_eq!(error.kind(), kind, "{error}");
        }
        assert_eq!(ErrorKind::InvalidPin.as_str(), "invalid_pin");
        assert_eq!(ErrorKind::InvalidInput.to_string(), "invalid_input");
    }

    #[test]
    fn guesses_remaining_is_structured() {
        let wrong_pin: SdkError = JuiceboxError::InvalidPin {
            guesses_remaining: Some(0),
        }
        .into();
        assert_eq!(wrong_pin.guesses_remaining(), Some(0));
        let no_count: SdkError = JuiceboxError::InvalidPin {
            guesses_remaining: None,
        }
        .into();
        assert_eq!(no_count.guesses_remaining(), None);
        assert_eq!(
            SdkError::InvalidInput("guesses_remaining=3".into()).guesses_remaining(),
            None
        );
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
