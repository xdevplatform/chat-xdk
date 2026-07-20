//! X Chat API I/O layer.
//!
//! The bot logic is written against the [`ChatApi`] trait so it stays
//! testable and free of any HTTP dependency. [`HttpChatApi`] is the HTTP
//! implementation (over `ureq`), compiled only with the `http` feature.

use chat_xdk_core::SigningKeyEntry;

/// One raw (encrypted) event from a conversation. `id` is the event's
/// sequence id (the API exposes sequence_id as id).
#[derive(Debug, Clone)]
pub struct EventItem {
    pub encoded_event: String,
    pub sender_id: String,
    pub id: String,
}

/// The X Chat API surface the bot needs.
pub trait ChatApi {
    fn get_my_user_id(&self) -> Result<String, String>;
    fn get_public_keys(&self, user_id: &str) -> Result<Vec<SigningKeyEntry>, String>;
    fn get_events(
        &self,
        conversation_id: &str,
        max_results: u32,
        pagination_token: Option<&str>,
    ) -> Result<(Vec<EventItem>, Option<String>), String>;
    fn send_message(
        &self,
        conversation_id: &str,
        body: &crate::chat_core::SendBody,
    ) -> Result<(), String>;
}

#[cfg(feature = "http")]
pub use http_impl::{HttpChatApi, RegisterError};

#[cfg(feature = "http")]
mod http_impl {
    use std::io::Read;

    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use serde_json::Value;

    use super::*;

    /// Failure modes of a public-key registration POST.
    #[derive(Debug)]
    pub enum RegisterError {
        /// HTTP 429 — the public-key write bucket is exhausted (only a few
        /// writes per 24h). `reset_epoch` is when the window frees up, if the
        /// server reported it; retrying before then just fails again.
        RateLimited { reset_epoch: Option<i64> },
        /// Any other failure.
        Other(String),
    }

    impl std::fmt::Display for RegisterError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                RegisterError::RateLimited { .. } => {
                    write!(f, "public-key registration rate limited (HTTP 429)")
                }
                RegisterError::Other(msg) => write!(f, "{msg}"),
            }
        }
    }

    /// String value of a JSON field that may arrive as a string or number.
    fn json_string(v: &Value) -> String {
        match v {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => String::new(),
        }
    }

    /// X Chat API client over HTTPS (ureq).
    pub struct HttpChatApi {
        base_url: String,
        access_token: String,
    }

    impl HttpChatApi {
        pub fn new(access_token: impl Into<String>, base_url: Option<String>) -> Self {
            Self {
                base_url: base_url.unwrap_or_else(|| "https://api.x.com".to_string()),
                access_token: access_token.into(),
            }
        }

        fn auth(&self) -> String {
            format!("Bearer {}", self.access_token)
        }

        fn get_json(&self, path: &str) -> Result<Value, String> {
            ureq::get(&format!("{}{}", self.base_url, path))
                .set("Authorization", &self.auth())
                .call()
                .map_err(|e| e.to_string())?
                .into_json::<Value>()
                .map_err(|e| e.to_string())
        }

        fn post_json(&self, path: &str, body: &Value) -> Result<Value, String> {
            let text = ureq::post(&format!("{}{}", self.base_url, path))
                .set("Authorization", &self.auth())
                .send_json(body.clone())
                .map_err(|e| e.to_string())?
                .into_string()
                .map_err(|e| e.to_string())?;
            if text.is_empty() {
                return Ok(Value::Object(Default::default()));
            }
            serde_json::from_str(&text).map_err(|e| e.to_string())
        }

        // -- Identity / registration ---------------------------------------

        /// Register a public key: POST /2/users/{id}/public_keys.
        ///
        /// `body` is the registration object from `generate_keypairs` in its
        /// snake_case wire form (`public_key` object, `version`,
        /// `generate_version`). Returns [`RegisterError::RateLimited`] on 429
        /// so the caller can stop instead of burning the strict daily budget.
        pub fn add_user_public_key(
            &self,
            user_id: &str,
            body: &Value,
        ) -> Result<Value, RegisterError> {
            let url = format!("{}/2/users/{user_id}/public_keys", self.base_url);
            match ureq::post(&url)
                .set("Authorization", &self.auth())
                .send_json(body.clone())
            {
                Ok(resp) => {
                    let text = resp
                        .into_string()
                        .map_err(|e| RegisterError::Other(e.to_string()))?;
                    if text.is_empty() {
                        return Ok(Value::Object(Default::default()));
                    }
                    serde_json::from_str(&text).map_err(|e| RegisterError::Other(e.to_string()))
                }
                Err(ureq::Error::Status(429, resp)) => Err(RegisterError::RateLimited {
                    reset_epoch: resp
                        .header("x-user-limit-24hour-reset")
                        .and_then(|s| s.parse::<i64>().ok()),
                }),
                Err(e) => Err(RegisterError::Other(e.to_string())),
            }
        }

        // -- Conversation / key management ---------------------------------

        /// POST a prepared conversation-key change (initialize or rotate).
        ///
        /// `body` is the REST shape built by `chat_core::prep_to_request`.
        /// For a 1:1, `conversation_id` may be the recipient's user ID; the
        /// server derives (and returns) the canonical conversation ID.
        pub fn add_conversation_keys(
            &self,
            conversation_id: &str,
            body: &Value,
        ) -> Result<Value, String> {
            let path = format!(
                "/2/chat/conversations/{}/keys",
                conversation_id.replace(':', "-")
            );
            self.post_json(&path, body)
        }

        /// Mint a new group conversation id (`g…`).
        pub fn initialize_group(&self) -> Result<String, String> {
            let v = self.post_json(
                "/2/chat/conversations/group/initialize",
                &Value::Object(Default::default()),
            )?;
            Ok(v["data"]["conversation_id"]
                .as_str()
                .unwrap_or("")
                .to_string())
        }

        /// POST /2/chat/conversations/group — create a group conversation.
        ///
        /// `body` carries `conversation_id`, `group_members`, `group_admins`,
        /// and the two-signature key change from `ChatCore::prepare_group_create`.
        pub fn create_conversation(&self, body: &Value) -> Result<Value, String> {
            self.post_json("/2/chat/conversations/group", body)
        }

        /// POST /2/chat/conversations/{id}/members — add members to a group.
        ///
        /// `body` carries `user_ids` plus the rotated key change from
        /// `ChatCore::prepare_group_members_change`.
        pub fn add_group_members(
            &self,
            conversation_id: &str,
            body: &Value,
        ) -> Result<Value, String> {
            let path = format!("/2/chat/conversations/{conversation_id}/members");
            self.post_json(&path, body)
        }

        // -- Media (encrypted blobs) -----------------------------------------

        /// Bytes per append segment when uploading media.
        const UPLOAD_CHUNK: usize = 3 * 1024 * 1024;

        /// Upload an encrypted media blob; returns its `media_hash_key`.
        ///
        /// Three-step flow: initialize (returns an upload session and the
        /// hash key), append (3 MB segments), finalize. The media endpoints
        /// take the colon form of the conversation id in the body.
        pub fn upload_media(
            &self,
            conversation_id: &str,
            ciphertext: &[u8],
        ) -> Result<String, String> {
            let conv = conversation_id.replace('-', ":");
            let init = self.post_json(
                "/2/chat/media/upload/initialize",
                &serde_json::json!({
                    "conversation_id": conv,
                    "total_bytes": ciphertext.len(),
                }),
            )?;
            let data = &init["data"];
            let session_id = data["session_id"]
                .as_str()
                .or_else(|| data["sessionId"].as_str())
                .unwrap_or("")
                .to_string();
            let media_hash_key = data["media_hash_key"]
                .as_str()
                .or_else(|| data["mediaHashKey"].as_str())
                .unwrap_or("")
                .to_string();
            if session_id.is_empty() || media_hash_key.is_empty() {
                return Err(format!("media upload initialize failed: {init}"));
            }

            let mut segment = 0;
            for chunk in ciphertext.chunks(Self::UPLOAD_CHUNK) {
                self.post_json(
                    &format!("/2/chat/media/upload/{session_id}/append"),
                    &serde_json::json!({
                        "conversation_id": conv,
                        "media_hash_key": media_hash_key,
                        "segment_index": segment.to_string(),
                        "media": B64.encode(chunk),
                    }),
                )?;
                segment += 1;
            }

            self.post_json(
                &format!("/2/chat/media/upload/{session_id}/finalize"),
                &serde_json::json!({
                    "conversation_id": conv,
                    "media_hash_key": media_hash_key,
                    "num_parts": segment.to_string(),
                }),
            )?;
            Ok(media_hash_key)
        }

        /// Download an encrypted media blob as raw bytes.
        ///
        /// The response body is binary ciphertext — it must be read as bytes;
        /// any text decoding would corrupt it. The download path takes the
        /// hyphen form of the conversation id.
        pub fn download_media(
            &self,
            conversation_id: &str,
            media_hash_key: &str,
        ) -> Result<Vec<u8>, String> {
            let path = format!(
                "/2/chat/media/{}/{media_hash_key}",
                conversation_id.replace(':', "-")
            );
            let resp = ureq::get(&format!("{}{}", self.base_url, path))
                .set("Authorization", &self.auth())
                .call()
                .map_err(|e| e.to_string())?;
            let mut bytes = Vec::new();
            resp.into_reader()
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            Ok(bytes)
        }
    }

    impl ChatApi for HttpChatApi {
        fn get_my_user_id(&self) -> Result<String, String> {
            let v = self.get_json("/2/users/me")?;
            v["data"]["id"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| "missing data.id".to_string())
        }

        // Every field of the public_key resource (public_key,
        // signing_public_key, identity_public_key_signature,
        // public_key_version, juicebox_config) is always included; the route
        // takes no public_key.fields parameter.
        fn get_public_keys(&self, user_id: &str) -> Result<Vec<SigningKeyEntry>, String> {
            let path = format!("/2/users/{user_id}/public_keys");
            let v = self.get_json(&path)?;
            let items = match &v["data"] {
                Value::Array(a) => a.clone(),
                Value::Object(_) => vec![v["data"].clone()],
                _ => vec![],
            };
            Ok(items
                .iter()
                .map(|pk| SigningKeyEntry {
                    user_id: user_id.to_string(),
                    public_key_version: pk["public_key_version"].as_str().unwrap_or("").to_string(),
                    public_key: pk["signing_public_key"].as_str().unwrap_or("").to_string(),
                    identity_public_key: pk["public_key"].as_str().unwrap_or("").to_string(),
                    identity_public_key_signature: pk["identity_public_key_signature"]
                        .as_str()
                        .unwrap_or("")
                        .to_string(),
                })
                .collect())
        }

        fn get_events(
            &self,
            conversation_id: &str,
            max_results: u32,
            pagination_token: Option<&str>,
        ) -> Result<(Vec<EventItem>, Option<String>), String> {
            let mut path = format!(
                "/2/chat/conversations/{}/events?max_results={max_results}",
                conversation_id.replace(':', "-")
            );
            if let Some(token) = pagination_token {
                path.push_str(&format!("&pagination_token={token}"));
            }
            let v = self.get_json(&path)?;
            let mut items = Vec::new();
            if let Value::Array(arr) = &v["data"] {
                for e in arr {
                    items.push(EventItem {
                        encoded_event: e["encoded_event"].as_str().unwrap_or("").to_string(),
                        sender_id: e["sender_id"].as_str().unwrap_or("").to_string(),
                        id: json_string(&e["id"]),
                    });
                }
            }
            let next = v["meta"]["next_token"].as_str().map(str::to_string);
            Ok((items, next))
        }

        fn send_message(
            &self,
            conversation_id: &str,
            body: &crate::chat_core::SendBody,
        ) -> Result<(), String> {
            let path = format!(
                "/2/chat/conversations/{}/messages",
                conversation_id.replace(':', "-")
            );
            ureq::post(&format!("{}{}", self.base_url, path))
                .set("Authorization", &self.auth())
                .send_json(serde_json::to_value(body).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            Ok(())
        }
    }
}
