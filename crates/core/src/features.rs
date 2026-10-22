//! Feature switches served by `GET /2/chat/features`.
//!
//! Internal: none of this is public API. The endpoint answers a flat map of
//! booleans, `{"features": {"v1_send": true}}`.
//!
//! Each chat reads the switches once, when it is created, and keeps the answer
//! for its lifetime. This module decides what to fetch and what an answer
//! means; it never performs a request. In this repository's language bindings
//! a chat's constructor starts its GET and the binding performs it with its
//! own HTTP stack (see `crate::bindings`); anywhere else no request is made
//! and every flag reads off. A chat created while a GET for its endpoint is in
//! flight takes that GET's answer instead of starting another.
//!
//! Every flag is off until the answer turns it on. A request that fails, takes
//! longer than its timeout (2 s), answers a status other than 200 or a body
//! over 64 KiB, or whose body is not a JSON object with a `features` object,
//! leaves every flag off. A flag whose value is not a boolean reads off.

// Without the bindings that perform the GETs, nothing here starts one.
#![cfg_attr(not(feature = "bindings"), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError, RwLock, Weak};

use crate::error::SdkError;

/// The flag that switches sends from the v0 wire format (0.5.x: contents under
/// the conversation key) to v1 (per-message keys).
pub const V1_SEND: &str = "v1_send";

/// URL of the feature-switch endpoint.
pub const FEATURES_ENDPOINT: &str = "https://api.x.com/2/chat/features";

/// Largest response body accepted, in bytes.
const MAX_BODY: usize = 64 * 1024;

/// How long a request may take, body included.
const TIMEOUT_MS: u64 = 2_000;

/// A GET for a language binding to perform.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Fetch {
    /// Identifies the request when its result is reported.
    pub id: u64,
    /// The full URL.
    pub url: String,
    /// The request must end within this time, body included.
    pub timeout_ms: u64,
    /// The largest body accepted: read at most one byte more, so a longer
    /// body is seen and rejected.
    pub max_bytes: usize,
}

/// The flags turned on for one chat, set once by the answer to its GET.
type Flags = RwLock<HashSet<String>>;

/// A GET in flight and the chats waiting for its answer.
#[derive(Debug)]
struct Request {
    id: u64,
    deadline: u64,
    chats: Vec<Weak<Flags>>,
}

/// The GETs in flight, by URL.
#[derive(Debug, Default)]
struct Requests {
    last_id: u64,
    by_url: HashMap<String, Request>,
}

impl Requests {
    /// Have the chat whose flags are `flags` read `url`: it joins the GET for
    /// `url` in flight, or starts one, returned for the binding to perform. A
    /// GET past its deadline takes no more chats.
    fn join(&mut self, url: &str, timeout_ms: u64, flags: &Arc<Flags>, now: u64) -> Option<Fetch> {
        if let Some(request) = self.by_url.get_mut(url) {
            if now < request.deadline {
                request.chats.push(Arc::downgrade(flags));
                return None;
            }
        }
        self.last_id += 1;
        let id = self.last_id;
        self.by_url.insert(
            url.to_string(),
            Request {
                id,
                deadline: now.saturating_add(timeout_ms),
                chats: vec![Arc::downgrade(flags)],
            },
        );
        Some(Fetch {
            id,
            url: url.to_string(),
            timeout_ms,
            max_bytes: MAX_BODY,
        })
    }

    /// Apply the result of the GET `id` to the chats waiting for it. A result
    /// for no GET in flight, or one that arrives after the GET's deadline,
    /// turns no flag on.
    fn complete(&mut self, id: u64, status: u16, body: &[u8], now: u64) {
        let Some(url) = self
            .by_url
            .iter()
            .find_map(|(url, request)| (request.id == id).then(|| url.clone()))
        else {
            return;
        };
        let Some(request) = self.by_url.remove(&url) else {
            return;
        };
        if now >= request.deadline {
            return;
        }
        let Some(flags) = parse_answer(status, body) else {
            return;
        };
        let on: HashSet<String> = flags
            .into_iter()
            .filter_map(|(name, enabled)| enabled.then_some(name))
            .collect();
        for chat in request.chats.iter().filter_map(Weak::upgrade) {
            *chat.write().unwrap_or_else(PoisonError::into_inner) = on.clone();
        }
    }
}

/// The flags of a 200 response whose body is a features object no larger than
/// [`MAX_BODY`].
fn parse_answer(status: u16, body: &[u8]) -> Option<HashMap<String, bool>> {
    if status != 200 || body.len() > MAX_BODY {
        return None;
    }
    parse_features(std::str::from_utf8(body).ok()?).ok()
}

/// Parse a features response: a JSON object whose `features` member is an
/// object. Members whose value is not a boolean are skipped; other top-level
/// members are ignored.
pub(crate) fn parse_features(json: &str) -> Result<HashMap<String, bool>, SdkError> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| SdkError::Parse(format!("features response is not JSON: {e}")))?;
    let features = value
        .get("features")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            SdkError::Parse("features response has no \"features\" object".to_string())
        })?;
    Ok(features
        .iter()
        .filter_map(|(name, value)| value.as_bool().map(|enabled| (name.clone(), enabled)))
        .collect())
}

/// The feature switches of one chat.
#[derive(Debug, Default)]
pub(crate) struct ChatFeatures {
    /// The endpoint this chat reads; the process default when unset.
    endpoint: Option<String>,
    /// The timeout of its GET; [`TIMEOUT_MS`] when unset.
    timeout_ms: Option<u64>,
    started: bool,
    flags: Arc<Flags>,
    #[cfg(test)]
    forced: Option<HashSet<String>>,
}

impl ChatFeatures {
    /// Whether the flag `name` is on for this chat.
    pub(crate) fn enabled(&self, name: &str) -> bool {
        #[cfg(test)]
        if let Some(forced) = &self.forced {
            return forced.contains(name);
        }
        self.flags
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(name)
    }

    /// Read `endpoint` within `timeout_ms`; only the GET started after this
    /// call uses them.
    pub(crate) fn configure(&mut self, endpoint: &str, timeout_ms: u64) {
        self.endpoint = Some(endpoint.to_string());
        self.timeout_ms = Some(timeout_ms);
    }

    /// Start this chat's one read of the switches: the GET to perform, or
    /// `None` when the chat takes the answer of a GET already in flight, has
    /// started its read already, or runs without the bindings.
    pub(crate) fn start(&mut self) -> Option<Fetch> {
        if std::mem::replace(&mut self.started, true) {
            return None;
        }
        #[cfg(feature = "bindings")]
        return shared::join(
            self.endpoint.as_deref(),
            self.timeout_ms.unwrap_or(TIMEOUT_MS),
            &self.flags,
        );
        #[cfg(not(feature = "bindings"))]
        None
    }

    /// Read exactly `on` as on, without any fetch.
    #[cfg(test)]
    pub(crate) fn force(&mut self, on: &[&str]) {
        self.forced = Some(on.iter().map(|name| name.to_string()).collect());
    }
}

/// The GETs every chat in the process shares, and what `crate::bindings`
/// exposes of them.
#[cfg(feature = "bindings")]
pub(crate) mod shared {
    use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, RwLock};

    use super::{Fetch, Flags, Requests, FEATURES_ENDPOINT};

    static DEFAULT_ENDPOINT: RwLock<Option<String>> = RwLock::new(None);
    static CLOCK: RwLock<Option<fn() -> u64>> = RwLock::new(None);

    fn requests() -> MutexGuard<'static, Requests> {
        static REQUESTS: OnceLock<Mutex<Requests>> = OnceLock::new();
        REQUESTS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Milliseconds on the registered clock, else on a monotonic system
    /// clock. WebAssembly has no system clock, so its binding registers one.
    fn now_ms() -> u64 {
        if let Some(clock) = *CLOCK.read().unwrap_or_else(PoisonError::into_inner) {
            return clock();
        }
        system_ms()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn system_ms() -> u64 {
        static START: OnceLock<std::time::Instant> = OnceLock::new();
        let elapsed = START.get_or_init(std::time::Instant::now).elapsed();
        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
    }

    #[cfg(target_arch = "wasm32")]
    fn system_ms() -> u64 {
        0
    }

    pub(crate) fn set_clock(clock: fn() -> u64) {
        *CLOCK.write().unwrap_or_else(PoisonError::into_inner) = Some(clock);
    }

    pub(crate) fn set_default_endpoint(endpoint: Option<&str>) {
        *DEFAULT_ENDPOINT
            .write()
            .unwrap_or_else(PoisonError::into_inner) = endpoint.map(str::to_string);
    }

    fn default_endpoint() -> String {
        DEFAULT_ENDPOINT
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| FEATURES_ENDPOINT.to_string())
    }

    pub(super) fn join(
        endpoint: Option<&str>,
        timeout_ms: u64,
        flags: &Arc<Flags>,
    ) -> Option<Fetch> {
        let url = endpoint.map_or_else(default_endpoint, str::to_string);
        requests().join(&url, timeout_ms, flags, now_ms())
    }

    pub(crate) fn complete_fetch(id: u64, status: u16, body: &[u8]) {
        requests().complete(id, status, body, now_ms());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://features.test/2/chat/features";
    const V1_ON: &[u8] = br#"{"features":{"v1_send":true}}"#;

    fn flags(json: &str) -> HashMap<String, bool> {
        parse_features(json).unwrap()
    }

    /// The flags of a new chat.
    fn chat() -> Arc<Flags> {
        Arc::default()
    }

    fn on(chat: &Flags, name: &str) -> bool {
        chat.read().unwrap().contains(name)
    }

    fn start(requests: &mut Requests, chat: &Arc<Flags>, now: u64) -> Fetch {
        requests
            .join(URL, TIMEOUT_MS, chat, now)
            .expect("a GET to perform")
    }

    #[test]
    fn parse_keeps_booleans_and_skips_everything_else() {
        let parsed = flags(
            r#"{"features":{"v1_send":true,"off":false,"n":1,"s":"true","z":null,"o":{}},"extra":1}"#,
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.get("v1_send"), Some(&true));
        assert_eq!(parsed.get("off"), Some(&false));
    }

    #[test]
    fn parse_rejects_bodies_without_a_features_object() {
        for body in [
            "",
            "not json",
            "[]",
            "null",
            r#"{"v1_send":true}"#,
            r#"{"features":[]}"#,
            r#"{"features":true}"#,
        ] {
            assert!(parse_features(body).is_err(), "{body:?}");
        }
        assert!(flags(r#"{"features":{}}"#).is_empty());
    }

    #[test]
    fn a_chat_starts_one_get_and_reads_off_until_its_answer() {
        let mut requests = Requests::default();
        let chat = chat();
        let fetch = start(&mut requests, &chat, 50);
        assert_eq!(fetch.url, URL);
        assert_eq!(fetch.timeout_ms, 2_000);
        assert_eq!(fetch.max_bytes, 64 * 1024);
        assert!(!on(&chat, V1_SEND), "off until the answer");

        requests.complete(fetch.id, 200, V1_ON, 300);
        assert!(on(&chat, V1_SEND));
        assert!(!on(&chat, "other"));
        assert!(requests.by_url.is_empty(), "nothing left in flight");
    }

    #[test]
    fn chats_created_while_a_get_is_in_flight_share_it() {
        let mut requests = Requests::default();
        let first = chat();
        let fetch = start(&mut requests, &first, 0);
        let others: Vec<Arc<Flags>> = (0..9).map(|_| chat()).collect();
        for other in &others {
            assert_eq!(
                requests.join(URL, TIMEOUT_MS, other, 10),
                None,
                "no second GET"
            );
        }

        requests.complete(fetch.id, 200, V1_ON, 100);
        assert!(on(&first, V1_SEND));
        assert!(others.iter().all(|chat| on(chat, V1_SEND)));
    }

    #[test]
    fn each_endpoint_has_its_own_get() {
        let mut requests = Requests::default();
        let a = requests.join(URL, TIMEOUT_MS, &chat(), 0).unwrap();
        let b = requests
            .join("https://elsewhere.test/features", TIMEOUT_MS, &chat(), 0)
            .unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(b.url, "https://elsewhere.test/features");
    }

    #[test]
    fn a_chat_created_after_the_answer_starts_its_own_get() {
        let mut requests = Requests::default();
        let first = chat();
        let fetch = start(&mut requests, &first, 0);
        requests.complete(fetch.id, 200, V1_ON, 10);

        let second = chat();
        let again = start(&mut requests, &second, 20);
        assert_ne!(again.id, fetch.id);
        assert!(!on(&second, V1_SEND), "no answer is reused");
        requests.complete(again.id, 200, br#"{"features":{"v1_send":false}}"#, 30);
        assert!(!on(&second, V1_SEND));
        assert!(
            on(&first, V1_SEND),
            "an answer holds for the chat's lifetime"
        );
    }

    #[test]
    fn every_kind_of_failure_leaves_every_flag_off() {
        let oversized = format!(
            r#"{{"features":{{"v1_send":true}}}}{}"#,
            " ".repeat(64 * 1024)
        );
        let cases: Vec<(u16, Vec<u8>)> = vec![
            (0, V1_ON.to_vec()),
            (404, V1_ON.to_vec()),
            (500, V1_ON.to_vec()),
            (204, Vec::new()),
            (200, b"not json".to_vec()),
            (200, br#"{"v1_send":true}"#.to_vec()),
            (200, br#"{"features":{"v1_send":"true"}}"#.to_vec()),
            (200, b"{\"features\":{\"v1_send\":true}}\xff".to_vec()),
            (200, oversized.into_bytes()),
        ];
        for (status, body) in cases {
            let mut requests = Requests::default();
            let chat = chat();
            let fetch = start(&mut requests, &chat, 0);
            requests.complete(fetch.id, status, &body, 10);
            assert!(!on(&chat, V1_SEND), "{status} {} bytes", body.len());
            assert!(requests.by_url.is_empty(), "the failed GET is done");
        }
    }

    #[test]
    fn a_body_exactly_at_the_limit_is_accepted() {
        let body = r#"{"features":{"v1_send":true}}"#;
        let padded = format!("{body}{}", " ".repeat(64 * 1024 - body.len()));
        let mut requests = Requests::default();
        let chat = chat();
        let fetch = start(&mut requests, &chat, 0);
        requests.complete(fetch.id, 200, padded.as_bytes(), 10);
        assert!(on(&chat, V1_SEND));
    }

    #[test]
    fn an_answer_after_the_deadline_is_ignored() {
        let mut requests = Requests::default();
        let chat = chat();
        let fetch = start(&mut requests, &chat, 0);
        requests.complete(fetch.id, 200, V1_ON, 2_000);
        assert!(!on(&chat, V1_SEND));
    }

    #[test]
    fn a_get_past_its_deadline_takes_no_more_chats() {
        let mut requests = Requests::default();
        let stuck = start(&mut requests, &chat(), 0);
        let late = chat();
        let fetch = start(&mut requests, &late, 2_000);
        assert_ne!(fetch.id, stuck.id, "a new GET");
        requests.complete(stuck.id, 200, V1_ON, 2_100);
        assert!(
            !on(&late, V1_SEND),
            "the old GET's result is for no GET in flight"
        );
        requests.complete(fetch.id, 200, V1_ON, 2_200);
        assert!(on(&late, V1_SEND));
    }

    #[test]
    fn an_unknown_or_repeated_result_changes_nothing() {
        let mut requests = Requests::default();
        let chat = chat();
        let fetch = start(&mut requests, &chat, 0);
        requests.complete(fetch.id + 100, 200, V1_ON, 10);
        assert!(!on(&chat, V1_SEND));
        requests.complete(fetch.id, 200, V1_ON, 20);
        assert!(on(&chat, V1_SEND));
        requests.complete(fetch.id, 200, br#"{"features":{}}"#, 30);
        assert!(on(&chat, V1_SEND), "the GET already completed");
    }

    #[test]
    fn a_dropped_chat_is_skipped() {
        let mut requests = Requests::default();
        let dropped = chat();
        let fetch = start(&mut requests, &dropped, 0);
        let kept = chat();
        assert_eq!(requests.join(URL, TIMEOUT_MS, &kept, 1), None);
        drop(dropped);
        requests.complete(fetch.id, 200, V1_ON, 10);
        assert!(on(&kept, V1_SEND));
    }

    #[test]
    fn a_chat_reads_once() {
        let mut features = ChatFeatures::default();
        features.configure(URL, 500);
        let first = features.start();
        #[cfg(feature = "bindings")]
        assert_eq!(
            first.map(|fetch| (fetch.url, fetch.timeout_ms)),
            Some((URL.to_string(), 500))
        );
        #[cfg(not(feature = "bindings"))]
        assert_eq!(first, None, "without the bindings no GET starts");
        assert_eq!(features.start(), None, "never a second read");
        assert!(!features.enabled(V1_SEND));
    }
}
