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

/// Where a Juicebox client takes the realms' auth tokens from.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "bindings"), allow(dead_code))]
enum TokenSource {
    /// The X API config carries them.
    Config,
    /// A callback supplies them.
    Callback,
}

/// Minimum PIN length in bytes accepted for new registrations.
#[cfg_attr(not(any(feature = "juicebox", feature = "bindings")), allow(dead_code))]
pub(crate) const MIN_PIN_LENGTH: usize = 4;

/// Validate PIN strength for new registrations.
///
/// Rejects PINs that are shorter than [`MIN_PIN_LENGTH`], use a single
/// repeated character (`0000`), or are an ascending/descending run of
/// digits (`1234`, `9876`). Applied when keys are registered and when the
/// PIN changes; never on unlock, so existing registrations stay
/// recoverable.
#[cfg_attr(not(any(feature = "juicebox", feature = "bindings")), allow(dead_code))]
pub(crate) fn validate_pin_strength(pin: &[u8]) -> Result<(), crate::error::SdkError> {
    use crate::error::{KeyError, SdkError};
    if pin.len() < MIN_PIN_LENGTH {
        return Err(SdkError::Key(KeyError::WeakPin(format!(
            "PIN must be at least {} characters",
            MIN_PIN_LENGTH
        ))));
    }
    if pin.iter().all(|&b| b == pin[0]) {
        return Err(SdkError::Key(KeyError::WeakPin(
            "PIN must not be a single repeated character".into(),
        )));
    }
    let ascending = pin.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
    let descending = pin.windows(2).all(|w| w[1] == w[0].wrapping_sub(1));
    if pin.iter().all(u8::is_ascii_digit) && (ascending || descending) {
        return Err(SdkError::Key(KeyError::WeakPin(
            "PIN must not be a sequential run of digits".into(),
        )));
    }
    Ok(())
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
    /// when the field is absent or not a count.
    ///
    /// Returns an error describing the first missing or malformed field.
    pub fn from_x_api_json(config_json: &str) -> Result<Self, String> {
        Self::parse_x_api_json(config_json, TokenSource::Config)
    }

    /// Like [`Self::from_x_api_json`], for a client that takes the realms'
    /// auth tokens from a callback: the config need carry none, and a raw
    /// Juicebox SDK config (an object with `realms`) is used verbatim.
    #[cfg_attr(not(feature = "bindings"), allow(dead_code))]
    pub(crate) fn from_x_api_json_without_tokens(config_json: &str) -> Result<Self, String> {
        Self::parse_x_api_json(config_json, TokenSource::Callback)
    }

    fn parse_x_api_json(config_json: &str, token_source: TokenSource) -> Result<Self, String> {
        let parsed: serde_json::Value =
            serde_json::from_str(config_json).map_err(|e| format!("Invalid JSON: {}", e))?;
        let tokens_required = token_source == TokenSource::Config;
        let max_guess_count = |default: u16| {
            parsed
                .get("max_guess_count")
                .and_then(|v| v.as_u64())
                .and_then(|n| u16::try_from(n).ok())
                .unwrap_or(default)
        };

        // Direct SDK config shape.
        if let Some(sdk_config_str) = parsed.get("sdk_config").and_then(|v| v.as_str()) {
            let mut tokens = HashMap::new();
            match parsed.get("tokens").and_then(|v| v.as_object()) {
                Some(tokens_obj) => {
                    for (k, v) in tokens_obj {
                        if let Some(token) = v.as_str() {
                            tokens.insert(k.clone(), token.to_string());
                        }
                    }
                }
                None if tokens_required => return Err("Missing tokens object".to_string()),
                None => {}
            }
            return Ok(Self::new(
                sdk_config_str.to_string(),
                tokens,
                max_guess_count(20),
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
            let tokens = if tokens_required {
                let token_map = parsed
                    .get("token_map")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| "Missing token_map".to_string())?;
                Self::tokens_from_token_map(token_map)?
            } else {
                HashMap::new()
            };
            return Ok(Self::new(
                sdk_config_str.to_string(),
                tokens,
                max_guess_count(20),
            ));
        }

        // A raw SDK config, for a client whose tokens come from elsewhere.
        if !tokens_required && parsed.get("realms").is_some() {
            return Ok(Self::new(
                config_json.to_string(),
                HashMap::new(),
                max_guess_count(5),
            ));
        }

        // Bare token_map shape.
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
            realms.push(serde_json::json!({"id": realm_id, "address": address}));
            if tokens_required {
                let token = value
                    .get("token")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "Missing token".to_string())?;
                tokens.insert(realm_id.to_string(), token.to_string());
            }
        }

        let sdk_config = serde_json::json!({
            "realms": realms,
            "register_threshold": realms.len(),
            "recover_threshold": (realms.len() / 2) + 1,
            "pin_hashing_mode": "Standard2019"
        });

        Ok(Self::new(
            sdk_config.to_string(),
            tokens,
            max_guess_count(5),
        ))
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

/// HTTP transport for Juicebox realm requests.
///
/// rustls with the bundled webpki roots, HTTP/2 and HTTP/1.1, and the system
/// proxy configuration. Every request carries `X-Juicebox-Version`, which
/// realms check to answer an outdated value with 426 (`UpgradeRequired`).
///
/// `User-Agent` is `juicebox_networking/<version>`. `ClientBuilder::reqwest`
/// inserts `JuiceboxSdk-Rust/<version>` and then `HashMap::extend`s
/// `juicebox_networking`'s default headers over it, so the networking crate's
/// agent string is the one that is sent.
#[cfg(feature = "juicebox")]
struct RealmHttpClient(reqwest::Client);

#[cfg(feature = "juicebox")]
impl RealmHttpClient {
    fn new() -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            juicebox_sdk::JUICEBOX_VERSION_HEADER,
            reqwest::header::HeaderValue::from_static(juicebox_sdk::VERSION),
        );
        let user_agent = format!("juicebox_networking/{}", juicebox_sdk::VERSION);
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_str(&user_agent)
                .expect("juicebox version is a valid user-agent"),
        );
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .tls_info(true)
            .use_rustls_tls()
            .default_headers(headers)
            .build()
            .expect("rustls client with bundled roots always builds");
        Self(client)
    }

    async fn fetch(
        &self,
        request: juicebox_sdk::http::Request,
    ) -> Result<juicebox_sdk::http::Response, reqwest::Error> {
        use juicebox_sdk::http::Method;
        use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
        use std::str::FromStr;

        let mut builder = match request.method {
            Method::Get => self.0.get(request.url),
            Method::Put => self.0.put(request.url),
            Method::Post => self.0.post(request.url),
            Method::Delete => self.0.delete(request.url),
        };
        // Same as juicebox_networking's reqwest adapter: drop a header the
        // HTTP stack rejects, and let a request header occupy the name a
        // default header already uses.
        let mut headers = HeaderMap::new();
        for (key, value) in &request.headers {
            if let (Ok(name), Ok(value)) = (HeaderName::from_str(key), HeaderValue::from_str(value))
            {
                headers.append(name, value);
            }
        }
        builder = builder.headers(headers);
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        if let Some(timeout) = request.timeout {
            builder = builder.timeout(timeout);
        }

        let response = builder.send().await?;
        let status_code = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| Some((name.to_string(), value.to_str().ok()?.to_owned())))
            .collect();
        let body = response.bytes().await?.to_vec();
        Ok(juicebox_sdk::http::Response {
            status_code,
            headers,
            body,
        })
    }
}

#[cfg(feature = "juicebox")]
#[async_trait]
impl juicebox_sdk::http::Client for RealmHttpClient {
    async fn send(
        &self,
        request: juicebox_sdk::http::Request,
    ) -> Option<juicebox_sdk::http::Response> {
        self.fetch(request).await.ok()
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
            .http(RealmHttpClient::new())
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
            .http(RealmHttpClient::new())
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
            .http(RealmHttpClient::new())
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
            // Conversion from the bare reason has no count; `Chat::unlock`
            // builds the variant directly to carry `guesses_remaining`.
            RecoverFailureReason::InvalidPin => JuiceboxError::InvalidPin {
                guesses_remaining: None,
            },
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

    #[test]
    fn a_client_with_callback_tokens_needs_none_in_the_config() {
        let sdk_config =
            JuiceboxConfig::from_x_api_json_without_tokens(r#"{"sdk_config": "{}"}"#).unwrap();
        assert_eq!(sdk_config.config_json, "{}");
        assert_eq!(sdk_config.max_guess_count, 20);
        assert!(JuiceboxConfig::from_x_api_json(r#"{"sdk_config": "{}"}"#).is_err());

        let token_map = JuiceboxConfig::from_x_api_json_without_tokens(
            r#"{"token_map": [{"key": "r1", "value": {"address": "https://r1.example"}}], "max_guess_count": 0}"#,
        )
        .unwrap();
        assert!(token_map.tokens.is_empty());
        assert_eq!(token_map.max_guess_count, 0);
        let sdk: serde_json::Value = serde_json::from_str(&token_map.config_json).unwrap();
        assert_eq!(sdk["realms"][0]["address"], "https://r1.example");

        let raw = r#"{"realms": [], "register_threshold": 1, "recover_threshold": 1}"#;
        let realms = JuiceboxConfig::from_x_api_json_without_tokens(raw).unwrap();
        assert_eq!(realms.config_json, raw);
        assert_eq!(realms.max_guess_count, 5);

        assert_eq!(
            JuiceboxConfig::from_x_api_json_without_tokens("{}").unwrap_err(),
            "Missing token_map or sdk_config"
        );
        let huge = JuiceboxConfig::from_x_api_json_without_tokens(
            r#"{"sdk_config": "{}", "max_guess_count": 70000}"#,
        )
        .unwrap();
        assert_eq!(huge.max_guess_count, 20);
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

    #[cfg(feature = "juicebox")]
    #[tokio::test]
    async fn test_realm_http_client_round_trip() {
        use juicebox_sdk::http::{Client as _, Method, Request};
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            while !String::from_utf8_lossy(&raw).ends_with("\r\n\r\nping") {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0, "connection closed before the full request");
                raw.extend_from_slice(&buf[..n]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 201 Created\r\nx-reply: yes\r\ncontent-length: 4\r\nconnection: close\r\n\r\npong",
                )
                .unwrap();
            String::from_utf8(raw).unwrap()
        });

        let response = RealmHttpClient::new()
            .send(Request {
                method: Method::Post,
                url: format!("http://{addr}/req"),
                headers: HashMap::from([("X-Custom".to_string(), "1".to_string())]),
                body: Some(b"ping".to_vec()),
                timeout: Some(std::time::Duration::from_secs(5)),
            })
            .await
            .expect("local server answers");
        let raw = server.join().unwrap().to_ascii_lowercase();

        assert!(raw.starts_with("post /req http/1.1\r\n"), "{raw}");
        let version = format!("\r\nx-juicebox-version: {}\r\n", juicebox_sdk::VERSION);
        let agent = format!(
            "\r\nuser-agent: juicebox_networking/{}\r\n",
            juicebox_sdk::VERSION
        );
        assert!(raw.contains(&version), "{raw}");
        assert!(raw.contains(&agent), "{raw}");
        assert!(
            !raw.contains("juiceboxsdk-rust"),
            "user-agent must be the juicebox_networking default, got {raw}"
        );
        assert!(raw.contains("\r\naccept: */*\r\n"), "{raw}");
        assert!(!raw.contains("accept-encoding"), "{raw}");
        assert!(raw.contains("\r\nx-custom: 1\r\n"), "{raw}");
        assert!(raw.contains("\r\ncontent-length: 4\r\n"), "{raw}");
        assert_eq!(response.status_code, 201);
        assert_eq!(
            response.headers.get("x-reply").map(String::as_str),
            Some("yes")
        );
        assert_eq!(response.body, b"pong");

        let unreachable = RealmHttpClient::new()
            .send(Request {
                method: Method::Get,
                url: format!("http://{addr}/gone"),
                headers: HashMap::new(),
                body: None,
                timeout: Some(std::time::Duration::from_secs(5)),
            })
            .await;
        assert!(unreachable.is_none());
    }

    /// Live TLS to the realm hosts in an X Chat `juicebox_config`.
    /// `CHAT_XDK_REALM_TLS=1 cargo test -p chat-xdk-core --features juicebox
    /// realm_hosts_complete_tls -- --nocapture --ignored`
    #[cfg(feature = "juicebox")]
    #[tokio::test]
    #[ignore]
    async fn realm_hosts_complete_tls() {
        use juicebox_sdk::http::{Client as _, Method, Request};

        let hosts = [
            "https://realm-b.x.com/",
            "https://realm-east1.x.com/",
            "https://realm-west1.x.com/",
        ];
        for url in hosts {
            let response = RealmHttpClient::new()
                .send(Request {
                    method: Method::Get,
                    url: url.to_string(),
                    headers: HashMap::new(),
                    body: None,
                    timeout: Some(std::time::Duration::from_secs(20)),
                })
                .await;
            let status = response.as_ref().map(|r| r.status_code);
            eprintln!("{url} status={status:?}");
            assert!(response.is_some(), "{url} TLS or HTTP failed");
        }
    }

    #[cfg(feature = "juicebox")]
    #[tokio::test]
    async fn test_realm_http_client_times_out_on_silent_server() {
        use juicebox_sdk::http::{Method, Request};
        use std::time::{Duration, Instant};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (release, held) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            let _ = held.recv();
        });

        let started = Instant::now();
        let err = RealmHttpClient::new()
            .fetch(Request {
                method: Method::Post,
                url: format!("http://{addr}/req"),
                headers: HashMap::new(),
                body: Some(b"ping".to_vec()),
                timeout: Some(Duration::from_millis(200)),
            })
            .await
            .expect_err("a server that never answers must time out");
        let elapsed = started.elapsed();
        drop(release);
        server.join().unwrap();

        assert!(err.is_timeout(), "{err:?}");
        assert!(
            elapsed >= Duration::from_millis(200) && elapsed < Duration::from_secs(5),
            "{elapsed:?}"
        );
    }
}
