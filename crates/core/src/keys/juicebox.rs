//! Juicebox SDK integration for secure key storage.
//!
//! This module provides the interface for storing and retrieving
//! identity/signing keys via the Juicebox SDK with PIN protection.
//!

use crate::error::JuiceboxError;
use std::collections::HashMap;
use zeroize::Zeroizing;

#[cfg(feature = "juicebox")]
use async_trait::async_trait;

#[cfg(feature = "juicebox")]
use juicebox_sdk::{
    AuthToken, AuthTokenManager, ClientBuilder, Configuration, DeleteError as JbDeleteError, Pin,
    Policy, RecoverError as JbRecoverError, RegisterError as JbRegisterError, UserInfo, UserSecret,
};

#[cfg(feature = "juicebox")]
use std::sync::Arc;

#[cfg(feature = "juicebox")]
use tokio::sync::RwLock;

/// Configuration for Juicebox SDK operations.
///
/// Contains auth tokens and realm configuration obtained from the X API.
#[derive(Clone)]
pub struct JuiceboxConfig {
    /// Auth tokens for Juicebox realms, keyed by realm ID.
    pub tokens: HashMap<String, String>,
    /// Maximum number of PIN guesses allowed.
    pub max_guess_count: u16,
    /// Raw JSON configuration from the X API.
    /// This is passed directly to the Juicebox SDK.
    pub config_json: String,
}

impl JuiceboxConfig {
    /// Create a new JuiceboxConfig from the X API response.
    ///
    /// # Arguments
    /// * `config_json` - The raw JSON configuration from the X API
    /// * `tokens` - Map of realm_id -> auth_token
    /// * `max_guess_count` - Maximum PIN guesses allowed
    pub fn new(config_json: String, tokens: HashMap<String, String>, max_guess_count: u16) -> Self {
        Self {
            tokens,
            max_guess_count,
            config_json,
        }
    }

    /// Create from just the config JSON (tokens will need to be added separately).
    pub fn from_json(config_json: String) -> Self {
        Self {
            tokens: HashMap::new(),
            max_guess_count: 5,
            config_json,
        }
    }

    /// Parse the X API Juicebox configuration JSON into a [`JuiceboxConfig`].
    ///
    /// Three shapes are accepted, checked in this order:
    /// - a direct SDK config: an `sdk_config` JSON string plus a `tokens` map
    ///   (realm id -> auth token), passed straight to the Juicebox SDK;
    /// - the X API `juicebox_config` object as returned by
    ///   `GET /2/users/:id/public_keys`: the `key_store_token_map_json` string
    ///   is used **verbatim** as the SDK config — it carries each realm's
    ///   `public_key` and the server's register/recover thresholds, which the
    ///   realms require — with auth tokens taken from the `token_map` array;
    /// - a bare `token_map` array of `{ key, value: { address, token } }`
    ///   entries (no `key_store_token_map_json`), converted into an SDK config
    ///   by deriving the realm list and majority register/recover thresholds
    ///   (`recover_threshold` is a simple majority so recovery survives a
    ///   minority of unavailable realms). This derivation cannot recover realm
    ///   public keys, so it only works against realms that don't require them.
    ///
    /// `max_guess_count` defaults to 20 for the direct SDK config and
    /// `key_store_token_map_json` shapes and 5 for the bare `token_map` shape
    /// when the field is absent.
    ///
    /// Returns an error describing the first missing or malformed field.
    pub fn from_x_api_json(config_json: &str) -> Result<Self, String> {
        let parsed: serde_json::Value =
            serde_json::from_str(config_json).map_err(|e| format!("Invalid JSON: {}", e))?;

        // Direct SDK config shape.
        if let Some(sdk_config_str) = parsed.get("sdk_config").and_then(|v| v.as_str()) {
            let tokens_obj = parsed
                .get("tokens")
                .and_then(|v| v.as_object())
                .ok_or_else(|| "Missing tokens object".to_string())?;
            let mut tokens = HashMap::new();
            for (k, v) in tokens_obj {
                if let Some(token) = v.as_str() {
                    tokens.insert(k.clone(), token.to_string());
                }
            }
            let max_guess_count = parsed
                .get("max_guess_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(20) as u16;
            return Ok(Self::new(
                sdk_config_str.to_string(),
                tokens,
                max_guess_count,
            ));
        }

        // X API `juicebox_config` shape: use the embedded SDK config verbatim
        // so realm public keys and server thresholds are preserved, and read
        // auth tokens from the accompanying `token_map`. A malformed embedded
        // config is an error — falling back to the lossy `token_map`
        // derivation would silently drop the realm public keys and produce
        // configs that can never reach the recover threshold.
        if let Some(key_store_json) = parsed.get("key_store_token_map_json") {
            let sdk_config_str = key_store_json
                .as_str()
                .ok_or_else(|| "key_store_token_map_json must be a string".to_string())?;
            let embedded = serde_json::from_str::<serde_json::Value>(sdk_config_str)
                .map_err(|e| format!("Invalid key_store_token_map_json: {}", e))?;
            if !embedded.is_object() {
                return Err("Invalid key_store_token_map_json: not a JSON object".to_string());
            }
            let token_map = parsed
                .get("token_map")
                .and_then(|v| v.as_array())
                .ok_or_else(|| "Missing token_map".to_string())?;
            let tokens = Self::tokens_from_token_map(token_map)?;
            let max_guess_count = parsed
                .get("max_guess_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(20) as u16;
            return Ok(Self::new(
                sdk_config_str.to_string(),
                tokens,
                max_guess_count,
            ));
        }

        // Bare token_map shape.
        let max_guess_count = parsed
            .get("max_guess_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(5) as u16;
        let token_map = parsed
            .get("token_map")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "Missing token_map or sdk_config".to_string())?;

        let mut realms = Vec::new();
        let mut tokens = HashMap::new();
        for entry in token_map {
            let realm_id = entry
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing key".to_string())?;
            let value = entry
                .get("value")
                .ok_or_else(|| "Missing value".to_string())?;
            let address = value
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing address".to_string())?;
            let token = value
                .get("token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing token".to_string())?;
            realms.push(serde_json::json!({"id": realm_id, "address": address}));
            tokens.insert(realm_id.to_string(), token.to_string());
        }

        let sdk_config = serde_json::json!({
            "realms": realms,
            "register_threshold": realms.len(),
            "recover_threshold": (realms.len() / 2) + 1,
            "pin_hashing_mode": "Standard2019"
        });

        Ok(Self::new(sdk_config.to_string(), tokens, max_guess_count))
    }

    /// Extract the realm id -> auth token map from an X API `token_map`
    /// array of `{ key, value: { token } }` entries. Used only by the
    /// `key_store_token_map_json` shape, where realm addresses come from the
    /// embedded SDK config; the bare `token_map` shape reads addresses and
    /// tokens in a single pass instead.
    fn tokens_from_token_map(
        token_map: &[serde_json::Value],
    ) -> Result<HashMap<String, String>, String> {
        let mut tokens = HashMap::new();
        for entry in token_map {
            let realm_id = entry
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing key".to_string())?;
            let token = entry
                .get("value")
                .ok_or_else(|| "Missing value".to_string())?
                .get("token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing token".to_string())?;
            tokens.insert(realm_id.to_string(), token.to_string());
        }
        Ok(tokens)
    }
}

// The token values are live bearer credentials for the Juicebox realms, so
// Debug prints only the realm ids they are keyed by. `config_json` carries
// realm addresses and thresholds, never tokens.
impl std::fmt::Debug for JuiceboxConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut realm_ids: Vec<&String> = self.tokens.keys().collect();
        realm_ids.sort();
        f.debug_struct("JuiceboxConfig")
            .field("token_realm_ids", &realm_ids)
            .field("max_guess_count", &self.max_guess_count)
            .field("config_json", &self.config_json)
            .finish()
    }
}

/// Result of a key recovery operation.
pub enum RecoverResult {
    /// Successfully recovered the key bytes.
    Success(Zeroizing<Vec<u8>>),
    /// Recovery failed with a specific reason.
    Failure {
        reason: RecoverFailureReason,
        guesses_remaining: Option<u16>,
    },
    /// Key reconstruction from recovered bytes failed.
    KeyReconstructionFailed,
    /// No Juicebox tokens available.
    NoTokens,
}

// `Success` carries the recovered identity/signing private key bytes, which
// must never appear in logs, so Debug redacts them.
impl std::fmt::Debug for RecoverResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoverResult::Success(_) => f.debug_tuple("Success").field(&"[REDACTED]").finish(),
            RecoverResult::Failure {
                reason,
                guesses_remaining,
            } => f
                .debug_struct("Failure")
                .field("reason", reason)
                .field("guesses_remaining", guesses_remaining)
                .finish(),
            RecoverResult::KeyReconstructionFailed => f.write_str("KeyReconstructionFailed"),
            RecoverResult::NoTokens => f.write_str("NoTokens"),
        }
    }
}

/// Reasons why key recovery can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverFailureReason {
    /// Wrong PIN provided.
    InvalidPin,
    /// Keys not registered yet.
    NotRegistered,
    /// Auth token is invalid.
    InvalidAuth,
    /// SDK version too old, upgrade required.
    UpgradeRequired,
    /// Internal assertion failure.
    Assertion,
    /// Transient network/backend error.
    Transient,
    /// Too many failed attempts.
    RateLimitExceeded,
}

impl RecoverFailureReason {
    /// Returns true if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            RecoverFailureReason::InvalidPin
                | RecoverFailureReason::NotRegistered
                | RecoverFailureReason::InvalidAuth
                | RecoverFailureReason::Transient
                | RecoverFailureReason::RateLimitExceeded
        )
    }
}

/// Result of a key registration operation.
#[derive(Debug)]
pub enum RegisterResult {
    /// Successfully registered the keys.
    Success,
    /// Registration failed with a specific reason.
    Failure(RegisterFailureReason),
}

/// Reasons why key registration can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterFailureReason {
    /// Auth token is invalid.
    InvalidAuth,
    /// SDK version too old, upgrade required.
    UpgradeRequired,
    /// Internal assertion failure.
    Assertion,
    /// Transient network/backend error.
    Transient,
    /// Too many attempts.
    RateLimitExceeded,
    /// Storage operation failed.
    StorageFailed,
}

impl RegisterFailureReason {
    /// Returns true if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            RegisterFailureReason::InvalidAuth
                | RegisterFailureReason::Transient
                | RegisterFailureReason::RateLimitExceeded
                | RegisterFailureReason::StorageFailed
        )
    }
}

/// Result of a key deletion operation.
#[derive(Debug)]
pub enum DeleteResult {
    /// Successfully deleted.
    Success,
    /// Deletion failed.
    Failure(DeleteFailureReason),
}

/// Reasons why key deletion can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteFailureReason {
    /// Auth token is invalid.
    InvalidAuth,
    /// SDK version too old.
    UpgradeRequired,
    /// Too many attempts.
    RateLimitExceeded,
    /// Internal assertion failure.
    Assertion,
    /// Transient network/backend error.
    Transient,
}

/// Trait for Juicebox SDK operations.
///
/// This trait abstracts the Juicebox SDK to allow for testing and
/// different implementations (native with reqwest, WASM with fetch, etc.).
#[cfg(feature = "juicebox")]
#[async_trait]
pub trait JuiceboxApi: Send + Sync {
    /// Register (store) private key bytes with PIN protection.
    ///
    /// # Arguments
    /// * `pin` - The user's PIN bytes (typically 4-6 digits); passed as
    ///   bytes so callers can zeroize their own buffer after the call
    /// * `config` - Juicebox configuration with auth tokens
    /// * `secret` - The secret bytes to store (identity + signing private keys)
    async fn register_private_key(
        &self,
        pin: &[u8],
        config: &JuiceboxConfig,
        secret: &[u8],
    ) -> RegisterResult;

    /// Recover (retrieve) private key bytes using PIN.
    ///
    /// # Arguments
    /// * `pin` - The user's PIN bytes
    /// * `config` - Juicebox configuration with auth tokens
    async fn recover_private_key(&self, pin: &[u8], config: &JuiceboxConfig) -> RecoverResult;

    /// Delete stored keys from Juicebox.
    ///
    /// Warning: This is irreversible. The user will lose access to their encrypted messages.
    async fn delete_keys(&self, config: &JuiceboxConfig) -> DeleteResult;
}

/// Auth token manager that uses a static map of tokens.
#[cfg(feature = "juicebox")]
struct StaticAuthTokenManager {
    tokens: Arc<RwLock<HashMap<String, String>>>,
}

#[cfg(feature = "juicebox")]
impl StaticAuthTokenManager {
    fn new(tokens: HashMap<String, String>) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(tokens)),
        }
    }
}

#[cfg(feature = "juicebox")]
#[async_trait]
impl AuthTokenManager for StaticAuthTokenManager {
    async fn get(&self, realm_id: &juicebox_sdk::RealmId) -> Option<AuthToken> {
        let tokens = self.tokens.read().await;
        let realm_id_hex = hex::encode(realm_id.0);
        tokens
            .get(&realm_id_hex)
            .map(|t| AuthToken::from(t.clone()))
    }
}

/// Juicebox client for PIN-protected key storage.
///
/// Communicates with Juicebox realms to securely store and recover keys.
/// This implementation uses reqwest for HTTP and tokio for async.
#[cfg(feature = "juicebox")]
pub struct JuiceboxClient;

#[cfg(feature = "juicebox")]
impl JuiceboxClient {
    /// Create a new Juicebox client.
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "juicebox")]
impl Default for JuiceboxClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "juicebox")]
#[async_trait]
impl JuiceboxApi for JuiceboxClient {
    async fn register_private_key(
        &self,
        pin: &[u8],
        config: &JuiceboxConfig,
        secret: &[u8],
    ) -> RegisterResult {
        // Parse configuration
        let configuration = match Configuration::from_json(&config.config_json) {
            Ok(c) => c,
            Err(_) => return RegisterResult::Failure(RegisterFailureReason::StorageFailed),
        };

        // Build client
        let auth_manager = StaticAuthTokenManager::new(config.tokens.clone());
        let client = ClientBuilder::new()
            .configuration(configuration)
            .tokio_sleeper()
            .reqwest()
            .auth_token_manager(auth_manager)
            .build();

        // Convert inputs. Pin and UserSecret zeroize their contents on drop,
        // so moving the copies in leaves no transient buffer to wipe here.
        let pin = Pin::from(pin.to_vec());
        let user_secret = UserSecret::from(secret.to_vec());
        // UserInfo is left empty; the same value must be used at registration
        // and recovery or recovery fails.
        let user_info = UserInfo::from(Vec::new());
        let policy = Policy {
            num_guesses: config.max_guess_count,
        };

        // Register
        match client
            .register(&pin, &user_secret, &user_info, policy)
            .await
        {
            Ok(()) => RegisterResult::Success,
            Err(e) => {
                let reason = match e {
                    JbRegisterError::InvalidAuth => RegisterFailureReason::InvalidAuth,
                    JbRegisterError::UpgradeRequired => RegisterFailureReason::UpgradeRequired,
                    JbRegisterError::Assertion => RegisterFailureReason::Assertion,
                    JbRegisterError::Transient => RegisterFailureReason::Transient,
                    JbRegisterError::RateLimitExceeded => RegisterFailureReason::RateLimitExceeded,
                };
                RegisterResult::Failure(reason)
            }
        }
    }

    async fn recover_private_key(&self, pin: &[u8], config: &JuiceboxConfig) -> RecoverResult {
        // Parse configuration
        let configuration = match Configuration::from_json(&config.config_json) {
            Ok(c) => c,
            Err(_) => {
                return RecoverResult::Failure {
                    reason: RecoverFailureReason::Transient,
                    guesses_remaining: None,
                }
            }
        };

        // Build client
        let auth_manager = StaticAuthTokenManager::new(config.tokens.clone());
        let client = ClientBuilder::new()
            .configuration(configuration)
            .tokio_sleeper()
            .reqwest()
            .auth_token_manager(auth_manager)
            .build();

        // Convert inputs. Pin zeroizes its contents on drop, so moving the
        // copy in leaves no transient buffer to wipe here.
        let pin = Pin::from(pin.to_vec());
        // UserInfo is left empty (must match registration).
        let user_info = UserInfo::from(Vec::new());

        // Recover
        match client.recover(&pin, &user_info).await {
            Ok(secret) => RecoverResult::Success(Zeroizing::new(secret.expose_secret().to_vec())),
            Err(e) => {
                let (reason, guesses) = match e {
                    JbRecoverError::InvalidPin { guesses_remaining } => {
                        (RecoverFailureReason::InvalidPin, Some(guesses_remaining))
                    }
                    JbRecoverError::NotRegistered => (RecoverFailureReason::NotRegistered, None),
                    JbRecoverError::InvalidAuth => (RecoverFailureReason::InvalidAuth, None),
                    JbRecoverError::UpgradeRequired => {
                        (RecoverFailureReason::UpgradeRequired, None)
                    }
                    JbRecoverError::Assertion => (RecoverFailureReason::Assertion, None),
                    JbRecoverError::Transient => (RecoverFailureReason::Transient, None),
                    JbRecoverError::RateLimitExceeded => {
                        (RecoverFailureReason::RateLimitExceeded, None)
                    }
                };
                RecoverResult::Failure {
                    reason,
                    guesses_remaining: guesses,
                }
            }
        }
    }

    async fn delete_keys(&self, config: &JuiceboxConfig) -> DeleteResult {
        let configuration = match Configuration::from_json(&config.config_json) {
            Ok(c) => c,
            Err(_) => return DeleteResult::Failure(DeleteFailureReason::Transient),
        };

        let auth_manager = StaticAuthTokenManager::new(config.tokens.clone());
        let client = ClientBuilder::new()
            .configuration(configuration)
            .tokio_sleeper()
            .reqwest()
            .auth_token_manager(auth_manager)
            .build();

        match client.delete().await {
            Ok(()) => DeleteResult::Success,
            Err(e) => {
                let reason = match e {
                    JbDeleteError::InvalidAuth => DeleteFailureReason::InvalidAuth,
                    JbDeleteError::UpgradeRequired => DeleteFailureReason::UpgradeRequired,
                    JbDeleteError::RateLimitExceeded => DeleteFailureReason::RateLimitExceeded,
                    JbDeleteError::Assertion => DeleteFailureReason::Assertion,
                    JbDeleteError::Transient => DeleteFailureReason::Transient,
                };
                DeleteResult::Failure(reason)
            }
        }
    }
}

impl From<RecoverFailureReason> for JuiceboxError {
    fn from(reason: RecoverFailureReason) -> Self {
        match reason {
            RecoverFailureReason::InvalidPin => JuiceboxError::InvalidPin,
            RecoverFailureReason::NotRegistered => JuiceboxError::NotRegistered,
            RecoverFailureReason::InvalidAuth => JuiceboxError::InvalidAuth,
            RecoverFailureReason::UpgradeRequired => JuiceboxError::UpgradeRequired,
            RecoverFailureReason::Assertion => JuiceboxError::Assertion,
            RecoverFailureReason::Transient => JuiceboxError::Transient,
            RecoverFailureReason::RateLimitExceeded => JuiceboxError::RateLimitExceeded,
        }
    }
}

impl From<RegisterFailureReason> for JuiceboxError {
    fn from(reason: RegisterFailureReason) -> Self {
        match reason {
            RegisterFailureReason::InvalidAuth => JuiceboxError::InvalidAuth,
            RegisterFailureReason::UpgradeRequired => JuiceboxError::UpgradeRequired,
            RegisterFailureReason::Assertion => JuiceboxError::Assertion,
            RegisterFailureReason::Transient => JuiceboxError::Transient,
            RegisterFailureReason::RateLimitExceeded => JuiceboxError::RateLimitExceeded,
            RegisterFailureReason::StorageFailed => JuiceboxError::StorageFailed,
        }
    }
}

/// Mock implementation for testing.
#[cfg(test)]
pub mod mock {
    use super::*;
    use std::sync::Mutex;

    /// A mock Juicebox API that stores keys in memory.
    pub struct MockJuiceboxApi {
        storage: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    }

    impl MockJuiceboxApi {
        /// Create a new empty mock.
        pub fn new() -> Self {
            Self {
                storage: Mutex::new(HashMap::new()),
            }
        }
    }

    impl Default for MockJuiceboxApi {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl JuiceboxApi for MockJuiceboxApi {
        async fn register_private_key(
            &self,
            pin: &[u8],
            _config: &JuiceboxConfig,
            secret: &[u8],
        ) -> RegisterResult {
            let mut storage = self.storage.lock().unwrap();
            storage.insert(pin.to_vec(), secret.to_vec());
            RegisterResult::Success
        }

        async fn recover_private_key(&self, pin: &[u8], _config: &JuiceboxConfig) -> RecoverResult {
            let storage = self.storage.lock().unwrap();
            match storage.get(pin) {
                Some(secret) => RecoverResult::Success(Zeroizing::new(secret.clone())),
                None => RecoverResult::Failure {
                    reason: RecoverFailureReason::NotRegistered,
                    guesses_remaining: None,
                },
            }
        }

        async fn delete_keys(&self, _config: &JuiceboxConfig) -> DeleteResult {
            let mut storage = self.storage.lock().unwrap();
            storage.clear();
            DeleteResult::Success
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_juicebox_config_from_json() {
        let config = JuiceboxConfig::from_json(r#"{"realms": []}"#.to_string());
        assert_eq!(config.max_guess_count, 5);
        assert!(config.tokens.is_empty());
    }

    #[test]
    fn test_from_x_api_json_sdk_config_shape() {
        let json = r#"{
            "sdk_config": "{\"realms\":[]}",
            "tokens": {"aabb": "tok-1"},
            "max_guess_count": 7
        }"#;
        let config = JuiceboxConfig::from_x_api_json(json).unwrap();
        assert_eq!(config.config_json, "{\"realms\":[]}");
        assert_eq!(config.max_guess_count, 7);
        assert_eq!(config.tokens.get("aabb").map(String::as_str), Some("tok-1"));
    }

    #[test]
    fn test_from_x_api_json_token_map_shape() {
        let json = r#"{
            "token_map": [
                {"key": "r1", "value": {"address": "https://r1.example", "token": "t1"}},
                {"key": "r2", "value": {"address": "https://r2.example", "token": "t2"}},
                {"key": "r3", "value": {"address": "https://r3.example", "token": "t3"}}
            ]
        }"#;
        let config = JuiceboxConfig::from_x_api_json(json).unwrap();
        // token_map shape defaults to 5 guesses.
        assert_eq!(config.max_guess_count, 5);
        assert_eq!(config.tokens.len(), 3);
        let sdk: serde_json::Value = serde_json::from_str(&config.config_json).unwrap();
        assert_eq!(sdk["register_threshold"], 3);
        // Majority recover threshold: (3 / 2) + 1 == 2.
        assert_eq!(sdk["recover_threshold"], 2);
        assert_eq!(sdk["pin_hashing_mode"], "Standard2019");
    }

    /// The X API `juicebox_config` object shape, as returned by
    /// `GET /2/users/:id/public_keys`. `key_store_token_map_json` carries the
    /// realm public keys and the server's thresholds.
    fn x_api_juicebox_config() -> String {
        let key_store = r#"{"realms":[{"id":"aa11","address":"https:\/\/realm-b.example\/"},{"id":"bb22","address":"https:\/\/realm-east.example\/","public_key":"e8b2205c63e448514a7579b1fc338e1f7442739ce3fd47fdafb916890d3e1341"},{"id":"cc33","address":"https:\/\/realm-west.example\/","public_key":"ca02aea58fd9529383fc179ccb1f8d3d80a63072567a78352568c2256a49821a"}],"register_threshold":3,"recover_threshold":2,"pin_hashing_mode":"Standard2019"}"#;
        serde_json::json!({
            "key_store_token_map_json": key_store,
            "max_guess_count": 20,
            "token_map": [
                {"key": "aa11", "value": {"address": "https://realm-b.example/", "token": "t1"}},
                {"key": "bb22", "value": {"address": "https://realm-east.example/", "token": "t2"}},
                {"key": "cc33", "value": {"address": "https://realm-west.example/", "token": "t3"}}
            ]
        })
        .to_string()
    }

    #[test]
    fn test_from_x_api_json_juicebox_config_shape_uses_key_store_verbatim() {
        let config = JuiceboxConfig::from_x_api_json(&x_api_juicebox_config()).unwrap();
        assert_eq!(config.max_guess_count, 20);
        assert_eq!(config.tokens.len(), 3);
        assert_eq!(config.tokens.get("bb22").map(String::as_str), Some("t2"));

        // The embedded SDK config must pass through unaltered: realm public
        // keys and the server's thresholds are required to reach the realms.
        let sdk: serde_json::Value = serde_json::from_str(&config.config_json).unwrap();
        assert_eq!(sdk["register_threshold"], 3);
        assert_eq!(sdk["recover_threshold"], 2);
        assert_eq!(
            sdk["realms"][1]["public_key"],
            "e8b2205c63e448514a7579b1fc338e1f7442739ce3fd47fdafb916890d3e1341"
        );
        assert_eq!(
            sdk["realms"][2]["public_key"],
            "ca02aea58fd9529383fc179ccb1f8d3d80a63072567a78352568c2256a49821a"
        );
    }

    #[test]
    fn test_from_x_api_json_juicebox_config_shape_defaults_guesses_to_20() {
        let mut parsed: serde_json::Value = serde_json::from_str(&x_api_juicebox_config()).unwrap();
        parsed.as_object_mut().unwrap().remove("max_guess_count");
        let config = JuiceboxConfig::from_x_api_json(&parsed.to_string()).unwrap();
        assert_eq!(config.max_guess_count, 20);
    }

    #[test]
    fn test_from_x_api_json_juicebox_config_shape_rejects_bad_key_store() {
        // A malformed embedded config must error, not silently fall back to
        // the lossy token_map derivation (which drops realm public keys).
        let json = serde_json::json!({
            "key_store_token_map_json": "not json",
            "token_map": [
                {"key": "aa11", "value": {"address": "https://realm-b.example/", "token": "t1"}}
            ]
        })
        .to_string();
        let err = JuiceboxConfig::from_x_api_json(&json).unwrap_err();
        assert!(err.contains("Invalid key_store_token_map_json"), "{err}");

        let json = serde_json::json!({
            "key_store_token_map_json": 42,
            "token_map": []
        })
        .to_string();
        let err = JuiceboxConfig::from_x_api_json(&json).unwrap_err();
        assert!(err.contains("must be a string"), "{err}");

        // Syntactically valid JSON that is not an object is rejected too,
        // rather than handed to the Juicebox SDK to fail obscurely at
        // setup/unlock time.
        for not_an_object in ["42", "[]", "null"] {
            let json = serde_json::json!({
                "key_store_token_map_json": not_an_object,
                "token_map": []
            })
            .to_string();
            let err = JuiceboxConfig::from_x_api_json(&json).unwrap_err();
            assert!(
                err.contains("Invalid key_store_token_map_json: not a JSON object"),
                "{err}"
            );
        }
    }

    #[test]
    fn test_from_x_api_json_juicebox_config_shape_requires_token_map() {
        let json = serde_json::json!({
            "key_store_token_map_json": "{\"realms\":[]}"
        })
        .to_string();
        let err = JuiceboxConfig::from_x_api_json(&json).unwrap_err();
        assert!(err.contains("Missing token_map"), "{err}");
    }

    #[test]
    fn test_from_x_api_json_missing_fields() {
        assert!(JuiceboxConfig::from_x_api_json("not json").is_err());
        assert!(JuiceboxConfig::from_x_api_json(r#"{"foo": 1}"#).is_err());
    }

    #[test]
    fn test_recover_result_debug_redaction() {
        let secret = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let debug = format!("{:?}", RecoverResult::Success(Zeroizing::new(secret)));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("170")); // 0xAA must not leak
        let failure = format!(
            "{:?}",
            RecoverResult::Failure {
                reason: RecoverFailureReason::InvalidPin,
                guesses_remaining: Some(3),
            }
        );
        assert!(failure.contains("InvalidPin"));
        assert!(failure.contains("3"));
    }

    #[test]
    fn test_juicebox_config_debug_redacts_tokens() {
        let mut tokens = HashMap::new();
        tokens.insert("realm-1".to_string(), "secret-bearer-token".to_string());
        let config = JuiceboxConfig::new(r#"{"realms":[]}"#.to_string(), tokens, 5);
        let debug = format!("{:?}", config);
        assert!(debug.contains("realm-1"));
        assert!(!debug.contains("secret-bearer-token"));
    }

    #[test]
    fn test_recover_failure_reason_retryable() {
        assert!(RecoverFailureReason::InvalidPin.is_retryable());
        assert!(RecoverFailureReason::Transient.is_retryable());
        assert!(!RecoverFailureReason::UpgradeRequired.is_retryable());
        assert!(!RecoverFailureReason::Assertion.is_retryable());
    }
}
