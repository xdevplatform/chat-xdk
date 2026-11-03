//! Feature switches for this repository's language bindings.
//!
//! Not part of the public API. A chat reads `GET /2/chat/features` when it is
//! created and again when its session identity gives it a new URL, retries a
//! read that fails, and reads again [`crate::FEATURES_REFRESH_MS`] after each
//! answer while it lives (see `crate::features`). The core decides what to
//! fetch, when to fetch it again and what an answer means; a binding only
//! performs the GETs, with its own HTTP stack. A binding's chat constructor,
//! and its `set_identity` once the core's has returned, call
//! [`FeatureSwitches::start_features`]. The binding performs the GET that
//! returns, if any, in the background after the GET's `delay_ms`, reports its
//! result with [`complete_fetch`], and performs the GET `complete_fetch`
//! returns, if any, the same way; it ends a GET it cannot start with
//! [`abandon_fetch`].

pub use crate::features::Fetch;

use std::collections::HashMap;

use crate::crypto::keys::XChatConversationKey;
use crate::error::{JuiceboxError, SdkError};
use crate::features::shared;
use crate::keys::juicebox::JuiceboxConfig;

/// The error document the C ABI returns for `error`: the kind, the message
/// and, for an invalid PIN that Juicebox reported a count for, the attempts
/// left.
pub fn error_document(error: &SdkError) -> String {
    let mut document = serde_json::json!({
        "kind": error.kind().as_str(),
        "message": error.to_string(),
    });
    if let Some(guesses_remaining) = error.guesses_remaining() {
        document["guesses_remaining"] = guesses_remaining.into();
    }
    document.to_string()
}

/// A conversation key map from raw key bytes, as the bindings receive it.
/// An entry that is not a 32-byte key is an error naming its version, the
/// first such version in sort order.
pub fn conversation_keys(
    entries: HashMap<String, Vec<u8>>,
) -> Result<HashMap<String, XChatConversationKey>, SdkError> {
    let mut entries: Vec<(String, Vec<u8>)> = entries.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
        .into_iter()
        .map(|(version, bytes)| {
            let key = XChatConversationKey::from_bytes(bytes).ok_or_else(|| {
                SdkError::InvalidInput(format!(
                    "the key for version '{}' in the conversation key map is not 32 bytes: \
                     pass the raw 32-byte conversation keys",
                    version
                ))
            })?;
            Ok((version, key))
        })
        .collect()
}

/// A conversation key from raw bytes, as `decrypt` takes it in the
/// bindings; anything but 32 bytes is an error.
pub fn conversation_key(bytes: &[u8]) -> Result<XChatConversationKey, SdkError> {
    crate::ChatCore::conversation_key_from_bytes(bytes)
}

/// Check a PIN for a binding that registers keys with Juicebox itself (the
/// JS binding), under the rule `setup` and `change_pin` apply.
pub fn validate_new_pin(pin: &[u8]) -> Result<(), SdkError> {
    crate::keys::juicebox::validate_pin_strength(pin)
}

/// The Juicebox SDK configuration and PIN guess budget of an X API Juicebox
/// config, for a binding that runs the Juicebox client itself and supplies
/// the realms' auth tokens from a callback (the JS binding).
pub fn juicebox_client_config(config_json: &str) -> Result<(String, u16), SdkError> {
    let config = JuiceboxConfig::from_x_api_json_without_tokens(config_json)?;
    Ok((config.config_json, config.max_guess_count))
}

/// The error a Juicebox call fails with on a chat that has no Juicebox
/// config, for a binding that runs the Juicebox client itself (the JS
/// binding): the error `Chat` returns in that state.
pub fn no_juicebox_config() -> SdkError {
    crate::keys::juicebox::no_config_error()
}

/// The error a Juicebox `operation` (`register`, `recover` or `delete`) of
/// a binding that runs the Juicebox client itself reports, from the
/// client's failure `reason` and guess count, so it carries the kind and
/// message every binding reports for that failure.
pub fn juicebox_error(operation: &str, reason: &str, guesses_remaining: Option<u16>) -> SdkError {
    let error = match (operation, reason) {
        ("delete", reason) => JuiceboxError::DeleteFailed(reason.to_string()),
        (_, "InvalidPin") => JuiceboxError::InvalidPin { guesses_remaining },
        (_, "NotRegistered") => JuiceboxError::NotRegistered,
        (_, "InvalidAuth") => JuiceboxError::InvalidAuth,
        (_, "UpgradeRequired") => JuiceboxError::UpgradeRequired,
        (_, "Assertion") => JuiceboxError::Assertion,
        (_, "Transient") => JuiceboxError::Transient,
        (_, "RateLimitExceeded") => JuiceboxError::RateLimitExceeded,
        (_, "StorageFailed") => JuiceboxError::StorageFailed,
        (_, reason) => JuiceboxError::Other(reason.to_string()),
    };
    SdkError::Juicebox(error)
}

/// Register the millisecond clock the core times GETs by. Only WebAssembly
/// needs one: it has no system clock.
pub fn set_clock(clock: fn() -> u64) {
    shared::set_clock(clock);
}

/// Report the result of the GET `id`: its HTTP status, 0 when no response
/// arrived, and the body, read to its end or to [`Fetch::max_bytes`] plus one
/// byte, whichever comes first. A request that ended any other way reports
/// status 0. Returns the next GET to perform, a refresh or a retry, while a
/// chat still waits for one.
pub fn complete_fetch(id: u64, status: u16, body: &[u8]) -> Option<Fetch> {
    shared::complete_fetch(id, status, body)
}

/// End the GET `id`, which the binding could not start, without a retry: the
/// next chat that reads the same URL starts a GET of its own, which also
/// answers the chats waiting for this one.
pub fn abandon_fetch(id: u64) {
    shared::abandon_fetch(id);
}

/// For this repository's tests: the endpoint of every chat that does not set
/// its own, or the X API's when `None`.
pub fn set_default_endpoint(endpoint: Option<&str>) {
    shared::set_default_endpoint(endpoint);
}

/// A chat's part in the feature switches, as the bindings drive it.
pub trait FeatureSwitches {
    /// For this repository's tests: read this chat's switches from
    /// `endpoint`, within `timeout_ms`, again `refresh_ms` after each answer
    /// and never more than `refresh_ms` apart while retrying. Only a read
    /// this chat starts after this call uses them.
    fn configure_features(&self, endpoint: &str, timeout_ms: u64, refresh_ms: u64);

    /// Start this chat's reads of the switches for its session identity,
    /// when it is created and again after `set_identity`: the GET to
    /// perform, or `None` when the chat shares a read of its identity's URL
    /// in flight or waiting to start.
    fn start_features(&self) -> Option<Fetch>;
}

impl FeatureSwitches for crate::ChatCore {
    fn configure_features(&self, endpoint: &str, timeout_ms: u64, refresh_ms: u64) {
        crate::ChatCore::configure_features(self, endpoint, timeout_ms, refresh_ms);
    }

    fn start_features(&self) -> Option<Fetch> {
        crate::ChatCore::start_features(self)
    }
}

#[cfg(feature = "juicebox")]
impl FeatureSwitches for crate::Chat {
    fn configure_features(&self, endpoint: &str, timeout_ms: u64, refresh_ms: u64) {
        FeatureSwitches::configure_features(self.core(), endpoint, timeout_ms, refresh_ms);
    }

    fn start_features(&self) -> Option<Fetch> {
        FeatureSwitches::start_features(self.core())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_documents_carry_the_kind_and_the_pin_count() {
        let wrong_pin = juicebox_error("recover", "InvalidPin", Some(2));
        let document: serde_json::Value =
            serde_json::from_str(&error_document(&wrong_pin)).unwrap();
        assert_eq!(
            document,
            serde_json::json!({
                "kind": "invalid_pin",
                "message": "Juicebox error: Invalid PIN: guesses_remaining=2",
                "guesses_remaining": 2,
            })
        );
        let other: serde_json::Value =
            serde_json::from_str(&error_document(&SdkError::Parse("bad".into()))).unwrap();
        assert_eq!(
            other,
            serde_json::json!({ "kind": "parse", "message": "Parse error: bad" })
        );
    }

    #[test]
    fn juicebox_errors_match_the_native_ones() {
        assert_eq!(
            juicebox_error("register", "InvalidAuth", None).to_string(),
            SdkError::Juicebox(JuiceboxError::InvalidAuth).to_string()
        );
        assert_eq!(
            juicebox_error("delete", "Transient", None).to_string(),
            "Juicebox error: Delete failed: Transient"
        );
        assert_eq!(
            juicebox_error("recover", "Unheard", None).kind(),
            crate::error::ErrorKind::Juicebox
        );
    }

    #[test]
    fn key_maps_and_pins_are_checked_in_the_core() {
        let keys = conversation_keys(HashMap::from([("7".to_string(), vec![1u8; 32])])).unwrap();
        assert_eq!(keys["7"].encoded(), &[1u8; 32]);
        let short =
            conversation_keys(HashMap::from([("8".to_string(), vec![1u8; 3])])).unwrap_err();
        assert_eq!(short.kind(), crate::error::ErrorKind::InvalidInput);
        assert!(short.to_string().contains("version '8'"));
        let versions = ["9", "10", "keys", "latestVersion", "2"];
        for _ in 0..8 {
            let bad = versions.iter().map(|v| (v.to_string(), vec![1u8; 3]));
            let err = conversation_keys(bad.collect()).unwrap_err();
            assert!(err.to_string().contains("version '10'"), "{err}");
        }
        assert_eq!(
            conversation_key(&[0u8; 5]).unwrap_err().to_string(),
            "Invalid conversation key (expected 32 bytes)"
        );
        assert_eq!(
            validate_new_pin(b"1234").unwrap_err().kind(),
            crate::error::ErrorKind::InvalidInput
        );
        assert!(validate_new_pin(b"2580").is_ok());
        let (sdk_config, guesses) =
            juicebox_client_config(r#"{"sdk_config": "{}", "max_guess_count": 3}"#).unwrap();
        assert_eq!((sdk_config.as_str(), guesses), ("{}", 3));
        assert!(juicebox_client_config("[]")
            .unwrap_err()
            .to_string()
            .starts_with("Invalid Juicebox config:"));
    }
}
