//! Feature switches served by `GET /2/chat/features`.
//!
//! The endpoint answers a flat map of booleans,
//! `{"features": {"v1_send": true}}`.
//!
//! A chat reads the switches when it is created and again whenever its
//! session identity gives it a new URL, then reads them again
//! [`FEATURES_REFRESH_MS`] after each answer while it lives, so a changed
//! answer reaches a running chat. This module decides what to fetch, when
//! to fetch it again and what an answer means; it never performs a request.
//! In this repository's language bindings the binding performs each GET the
//! core hands back with its own HTTP stack (see `crate::bindings`); a Rust
//! caller performs the GETs and hands each answer to
//! `ChatCore::set_feature_switches`.
//!
//! A chat with a session identity asks for its sender's bucket, the last
//! four digits of its user id, so every chat of one sender gets the same
//! answer wherever it runs; a chat without one asks without a bucket. Chats
//! that read the same URL share one read: a chat that joins it takes the
//! latest answer at once.
//!
//! Every flag is off until an answer turns it on, and each answer replaces
//! the one before. A read fails when the request fails or outlasts its
//! timeout (2 s), or when the response's status is not 200, its body is
//! over 64 KiB, or its body is not a JSON object with a `features` object.
//! A failed read changes no flag and is retried after
//! [`RETRY_FIRST_DELAY_MS`], then after twice the previous wait, never more
//! than [`FEATURES_REFRESH_MS`] apart, with no limit on retries. Reads stop
//! once no chat waits for them. A flag whose value is not a boolean reads
//! off.

// Without the bindings that perform the GETs, nothing here starts one.
#![cfg_attr(not(feature = "bindings"), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError, RwLock, Weak};

use crate::error::SdkError;

/// The flag that switches sends from the v0 wire format (0.5.x: contents under
/// the conversation key) to v1 (per-message keys).
pub const V1_SEND: &str = "v1_send";

/// The URL of the X API's feature switches, `GET /2/chat/features`. Request
/// it without credentials; a chat's request adds its sender's bucket (see
/// `ChatCore::feature_switches_url`).
pub const FEATURES_ENDPOINT: &str = "https://api.x.com/2/chat/features";

/// Largest response body accepted, in bytes.
pub const FEATURES_MAX_BODY: usize = 64 * 1024;

/// How long a request may take, body included, in milliseconds.
pub const FEATURES_TIMEOUT_MS: u64 = 2_000;

/// How long after an answer a chat reads its switches again, and the longest
/// wait before a retry, in milliseconds.
pub const FEATURES_REFRESH_MS: u64 = 5 * 60 * 1_000;

/// The wait before the first retry of a read that failed, in milliseconds.
pub(crate) const RETRY_FIRST_DELAY_MS: u64 = 1_000;

/// The bucket of the sender `user_id`: its last four digits. `None` for an id
/// that is not a string of digits.
pub(crate) fn bucket(user_id: &str) -> Option<u16> {
    if user_id.is_empty() || !user_id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    user_id[user_id.len().saturating_sub(4)..].parse().ok()
}

/// The URL a chat reads its switches from: `endpoint`, with the bucket of
/// `user_id` when there is one.
pub(crate) fn features_url(endpoint: &str, user_id: Option<&str>) -> String {
    match user_id.and_then(bucket) {
        Some(bucket) => {
            let separator = if endpoint.contains('?') { '&' } else { '?' };
            format!("{endpoint}{separator}bucket={bucket}")
        }
        None => endpoint.to_string(),
    }
}

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
    /// Start the request this long from now: 0 for a chat's first read, the
    /// wait for a retry or a refresh.
    pub delay_ms: u64,
}

/// The flags turned on for one chat, set by each answer to its reads.
type Flags = RwLock<HashSet<String>>;

/// A read in flight, or waiting to start, and the chats waiting for its
/// answer.
#[derive(Debug)]
struct Request {
    id: u64,
    timeout_ms: u64,
    refresh_ms: u64,
    /// How many reads in a row failed before this one.
    failures: u32,
    /// When this read's result stops counting and it takes no more chats:
    /// its start plus its timeout; 0 once abandoned.
    deadline: u64,
    chats: Vec<Weak<Flags>>,
    /// The flags the latest answer turned on, which a chat that joins takes.
    answer: Option<HashSet<String>>,
}

/// The wait before the read that follows `failures` failed ones in a row:
/// [`RETRY_FIRST_DELAY_MS`], doubling, never more than `refresh_ms`.
fn retry_delay_ms(failures: u32, refresh_ms: u64) -> u64 {
    RETRY_FIRST_DELAY_MS
        .saturating_mul(1u64 << failures.saturating_sub(1).min(32))
        .min(refresh_ms)
}

/// The reads in flight or waiting to start, by URL.
#[derive(Debug, Default)]
struct Requests {
    last_id: u64,
    by_url: HashMap<String, Request>,
}

impl Requests {
    /// Have the chat whose flags are `flags` read `url`. It takes the latest
    /// answer for `url` at once, if any, then joins the read of `url` in
    /// flight or waiting to start, once however often it joins; otherwise it
    /// starts a read, which is returned for the binding to perform. A read
    /// past its deadline takes no more chats: its late result changes
    /// nothing, so the read that replaces it carries over its chats and its
    /// answer.
    fn join(
        &mut self,
        url: &str,
        timeout_ms: u64,
        refresh_ms: u64,
        flags: &Arc<Flags>,
        now: u64,
    ) -> Option<Fetch> {
        let joining = Arc::downgrade(flags);
        // Chats that are gone, and the joining chat's earlier entry, leave
        // the list, so it holds each live chat once.
        let other = |chat: &Weak<Flags>| chat.strong_count() > 0 && !chat.ptr_eq(&joining);
        if let Some(request) = self.by_url.get_mut(url) {
            if let Some(answer) = &request.answer {
                answer.clone_into(&mut flags.write().unwrap_or_else(PoisonError::into_inner));
            }
            if now < request.deadline {
                request.chats.retain(other);
                request.chats.push(joining);
                return None;
            }
        }
        let mut request = Request {
            id: 0,
            timeout_ms,
            refresh_ms,
            failures: 0,
            deadline: 0,
            chats: vec![joining.clone()],
            answer: None,
        };
        if let Some(expired) = self.by_url.remove(url) {
            request
                .chats
                .extend(expired.chats.into_iter().filter(|chat| other(chat)));
            request.answer = expired.answer;
        }
        Some(self.schedule(url, request, 0, now))
    }

    /// End the read `id`, which its binding could not start, without a
    /// retry: the next chat that joins starts a read of its own, which also
    /// answers the chats waiting for this one.
    fn abandon(&mut self, id: u64) {
        if let Some(request) = self.by_url.values_mut().find(|request| request.id == id) {
            // No read has id 0, so a result reported for this one changes
            // nothing.
            request.id = 0;
            request.deadline = 0;
        }
    }

    /// Register `request` as the read of `url` under a new id, to start
    /// `delay_ms` from `now`, and return it for the binding to perform.
    fn schedule(&mut self, url: &str, mut request: Request, delay_ms: u64, now: u64) -> Fetch {
        self.last_id += 1;
        request.id = self.last_id;
        request.deadline = now
            .saturating_add(delay_ms)
            .saturating_add(request.timeout_ms);
        let fetch = Fetch {
            id: request.id,
            url: url.to_string(),
            timeout_ms: request.timeout_ms,
            max_bytes: FEATURES_MAX_BODY,
            delay_ms,
        };
        self.by_url.insert(url.to_string(), request);
        fetch
    }

    /// Apply the result of the read `id` to the chats waiting for it, and
    /// return the next read for the binding to perform while a chat still
    /// waits: a refresh after an answer, a retry after a result that is no
    /// answer (a failure, or a response after the read's deadline). A result
    /// for no read in flight changes nothing.
    fn complete(&mut self, id: u64, status: u16, body: &[u8], now: u64) -> Option<Fetch> {
        let url = self
            .by_url
            .iter()
            .find_map(|(url, request)| (id != 0 && request.id == id).then(|| url.clone()))?;
        let mut request = self.by_url.remove(&url)?;
        request.chats.retain(|chat| chat.strong_count() > 0);
        let answer = if now < request.deadline {
            parse_answer(status, body)
        } else {
            None
        };
        let delay_ms = match answer {
            Some(on) => {
                for chat in request.chats.iter().filter_map(Weak::upgrade) {
                    on.clone_into(&mut chat.write().unwrap_or_else(PoisonError::into_inner));
                }
                request.answer = Some(on);
                request.failures = 0;
                request.refresh_ms
            }
            None => {
                request.failures = request.failures.saturating_add(1);
                retry_delay_ms(request.failures, request.refresh_ms)
            }
        };
        if request.chats.is_empty() {
            return None;
        }
        Some(self.schedule(&url, request, delay_ms, now))
    }
}

/// The flags a 200 response turns on, when its body is a features object no
/// larger than [`FEATURES_MAX_BODY`].
fn parse_answer(status: u16, body: &[u8]) -> Option<HashSet<String>> {
    if status != 200 || body.len() > FEATURES_MAX_BODY {
        return None;
    }
    let flags = parse_features(std::str::from_utf8(body).ok()?).ok()?;
    Some(
        flags
            .into_iter()
            .filter_map(|(name, enabled)| enabled.then_some(name))
            .collect(),
    )
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
    /// The timeout of its reads; [`FEATURES_TIMEOUT_MS`] when unset.
    timeout_ms: Option<u64>,
    /// The wait between its answers and its next reads;
    /// [`FEATURES_REFRESH_MS`] when unset.
    refresh_ms: Option<u64>,
    /// The URL of the read this chat takes part in, once it reads its own;
    /// until then its answers come from the caller.
    url: Option<String>,
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

    /// Read `endpoint` within `timeout_ms`, again `refresh_ms` after each
    /// answer and never more than `refresh_ms` apart while retrying; only a
    /// read this chat starts after this call uses them.
    pub(crate) fn configure(&mut self, endpoint: &str, timeout_ms: u64, refresh_ms: u64) {
        self.endpoint = Some(endpoint.to_string());
        self.timeout_ms = Some(timeout_ms);
        self.refresh_ms = Some(refresh_ms);
    }

    /// Start this chat's reads of the switches for the sender `user_id`, or
    /// move them to that sender's URL: the read to perform, or `None` when
    /// the chat shares a read of that URL in flight or waiting to start, or
    /// runs without the bindings. A chat that moves turns every flag off
    /// until its new URL answers, unless the shared read of that URL already
    /// holds an answer. A chat that starts again on the URL it reads rejoins
    /// its read, or starts one when its binding abandoned the last.
    pub(crate) fn start(&mut self, user_id: Option<&str>) -> Option<Fetch> {
        #[cfg(feature = "bindings")]
        {
            let url = shared::url(self.endpoint.as_deref(), user_id);
            if self.url.as_deref() != Some(url.as_str()) && self.url.replace(url.clone()).is_some()
            {
                self.flags = Arc::default();
            }
            shared::join(
                &url,
                self.timeout_ms.unwrap_or(FEATURES_TIMEOUT_MS),
                self.refresh_ms.unwrap_or(FEATURES_REFRESH_MS),
                &self.flags,
            )
        }
        #[cfg(not(feature = "bindings"))]
        {
            let _ = user_id;
            None
        }
    }

    /// Take `status` and `body`, the answer to a read the caller performed,
    /// unless this chat reads its own. An answer replaces the one before; a
    /// status and body that are no answer (see [`parse_answer`]) change
    /// nothing.
    pub(crate) fn answer(&mut self, status: u16, body: &[u8]) {
        if self.url.is_some() {
            return;
        }
        if let Some(on) = parse_answer(status, body) {
            *self.flags.write().unwrap_or_else(PoisonError::into_inner) = on;
        }
    }

    /// Read exactly `on` as on, without any fetch.
    #[cfg(test)]
    pub(crate) fn force(&mut self, on: &[&str]) {
        self.forced = Some(on.iter().map(|name| name.to_string()).collect());
    }
}

/// The reads every chat in the process shares, and what `crate::bindings`
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

    pub(super) fn url(endpoint: Option<&str>, user_id: Option<&str>) -> String {
        super::features_url(
            &endpoint.map_or_else(default_endpoint, str::to_string),
            user_id,
        )
    }

    pub(super) fn join(
        url: &str,
        timeout_ms: u64,
        refresh_ms: u64,
        flags: &Arc<Flags>,
    ) -> Option<Fetch> {
        requests().join(url, timeout_ms, refresh_ms, flags, now_ms())
    }

    pub(crate) fn complete_fetch(id: u64, status: u16, body: &[u8]) -> Option<Fetch> {
        requests().complete(id, status, body, now_ms())
    }

    pub(crate) fn abandon_fetch(id: u64) {
        requests().abandon(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://features.test/2/chat/features";
    const V1_ON: &[u8] = br#"{"features":{"v1_send":true}}"#;
    const V1_OFF: &[u8] = br#"{"features":{"v1_send":false}}"#;

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

    fn join(requests: &mut Requests, chat: &Arc<Flags>, now: u64) -> Option<Fetch> {
        requests.join(URL, FEATURES_TIMEOUT_MS, FEATURES_REFRESH_MS, chat, now)
    }

    fn start(requests: &mut Requests, chat: &Arc<Flags>, now: u64) -> Fetch {
        join(requests, chat, now).expect("a GET to perform")
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
    fn a_senders_bucket_is_the_last_four_digits_of_its_user_id() {
        assert_eq!(bucket("1234567890"), Some(7890));
        assert_eq!(bucket("1230042"), Some(42));
        assert_eq!(bucket("42"), Some(42));
        assert_eq!(bucket("10000"), Some(0));
        for not_digits in ["", "12a", "-42", "+42", " 42"] {
            assert_eq!(bucket(not_digits), None, "{not_digits:?}");
        }
        assert_eq!(
            features_url(URL, Some("1234567890")),
            format!("{URL}?bucket=7890")
        );
        assert_eq!(
            features_url("https://features.test/f?x=1", Some("42")),
            "https://features.test/f?x=1&bucket=42"
        );
        assert_eq!(features_url(URL, None), URL);
        assert_eq!(features_url(URL, Some("no id")), URL);
    }

    #[test]
    fn a_chat_starts_one_get_and_reads_off_until_its_answer() {
        let mut requests = Requests::default();
        let chat = chat();
        let fetch = start(&mut requests, &chat, 50);
        assert_eq!(fetch.url, URL);
        assert_eq!(fetch.timeout_ms, 2_000);
        assert_eq!(fetch.max_bytes, 64 * 1024);
        assert_eq!(fetch.delay_ms, 0, "a first read starts at once");
        assert!(!on(&chat, V1_SEND), "off until the answer");

        let refresh = requests.complete(fetch.id, 200, V1_ON, 300).unwrap();
        assert!(on(&chat, V1_SEND));
        assert!(!on(&chat, "other"));
        assert_eq!(
            (refresh.url.as_str(), refresh.delay_ms),
            (URL, FEATURES_REFRESH_MS),
            "the next read follows the refresh interval"
        );
    }

    #[test]
    fn chats_created_while_a_get_is_in_flight_share_it() {
        let mut requests = Requests::default();
        let first = chat();
        let fetch = start(&mut requests, &first, 0);
        let others: Vec<Arc<Flags>> = (0..9).map(|_| chat()).collect();
        for other in &others {
            assert_eq!(join(&mut requests, other, 10), None, "no second GET");
        }

        requests.complete(fetch.id, 200, V1_ON, 100);
        assert!(on(&first, V1_SEND));
        assert!(others.iter().all(|chat| on(chat, V1_SEND)));
    }

    #[test]
    fn each_url_has_its_own_get() {
        let mut requests = Requests::default();
        let a = start(&mut requests, &chat(), 0);
        let b = requests
            .join(
                &features_url(URL, Some("1001")),
                FEATURES_TIMEOUT_MS,
                FEATURES_REFRESH_MS,
                &chat(),
                0,
            )
            .unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(b.url, format!("{URL}?bucket=1001"));
    }

    #[test]
    fn each_refresh_replaces_the_answer() {
        let mut requests = Requests::default();
        let chat = chat();
        let fetch = start(&mut requests, &chat, 0);
        let refresh = requests.complete(fetch.id, 200, V1_ON, 10).unwrap();
        assert!(on(&chat, V1_SEND));
        let next = requests
            .complete(refresh.id, 200, V1_OFF, 10 + FEATURES_REFRESH_MS + 100)
            .unwrap();
        assert!(!on(&chat, V1_SEND), "the refresh turned it off");
        assert_eq!(next.delay_ms, FEATURES_REFRESH_MS);
        requests.complete(next.id, 200, V1_ON, 20 + 2 * FEATURES_REFRESH_MS + 100);
        assert!(on(&chat, V1_SEND), "and on again");
    }

    #[test]
    fn a_chat_created_after_an_answer_takes_it_at_once_and_shares_the_refresh() {
        let mut requests = Requests::default();
        let first = chat();
        let fetch = start(&mut requests, &first, 0);
        let refresh = requests.complete(fetch.id, 200, V1_ON, 10).unwrap();

        let second = chat();
        assert_eq!(join(&mut requests, &second, 20), None, "no GET of its own");
        assert!(on(&second, V1_SEND), "the latest answer, at once");
        requests.complete(refresh.id, 200, V1_OFF, 10 + FEATURES_REFRESH_MS + 100);
        assert!(!on(&first, V1_SEND) && !on(&second, V1_SEND));
    }

    #[test]
    fn every_kind_of_failure_leaves_every_flag_off_and_is_retried() {
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
            (200, b"{\"features\":{\"v1_send\":true}}\xff".to_vec()),
            (200, oversized.into_bytes()),
        ];
        for (status, body) in cases {
            let mut requests = Requests::default();
            let chat = chat();
            let fetch = start(&mut requests, &chat, 0);
            let retry = requests
                .complete(fetch.id, status, &body, 10)
                .expect("a retry");
            assert!(!on(&chat, V1_SEND), "{status} {} bytes", body.len());
            assert_ne!(retry.id, fetch.id, "a GET of its own");
            assert_eq!(
                (retry.url.as_str(), retry.timeout_ms, retry.delay_ms),
                (URL, FEATURES_TIMEOUT_MS, RETRY_FIRST_DELAY_MS)
            );
        }
    }

    #[test]
    fn a_failed_refresh_keeps_the_answer_and_is_retried() {
        let mut requests = Requests::default();
        let chat = chat();
        let fetch = start(&mut requests, &chat, 0);
        let refresh = requests.complete(fetch.id, 200, V1_ON, 10).unwrap();
        let retry = requests
            .complete(refresh.id, 503, b"", 10 + FEATURES_REFRESH_MS + 100)
            .unwrap();
        assert!(on(&chat, V1_SEND), "the last answer holds");
        assert_eq!(retry.delay_ms, RETRY_FIRST_DELAY_MS);
    }

    #[test]
    fn a_flag_that_is_not_a_boolean_reads_off() {
        let mut requests = Requests::default();
        let chat = chat();
        let fetch = start(&mut requests, &chat, 0);
        let body = br#"{"features":{"v1_send":"true"}}"#;
        let next = requests.complete(fetch.id, 200, body, 10).unwrap();
        assert!(!on(&chat, V1_SEND));
        assert_eq!(next.delay_ms, FEATURES_REFRESH_MS, "an answer, refreshed");
    }

    #[test]
    fn a_read_that_keeps_failing_is_retried_with_a_doubling_wait_up_to_the_refresh() {
        let mut requests = Requests::default();
        let chat = chat();
        let mut fetch = start(&mut requests, &chat, 0);
        let mut now = 0;
        let mut waits = Vec::new();
        for _ in 0..12 {
            let retry = requests.complete(fetch.id, 503, b"", now + 100).unwrap();
            now += 100 + retry.delay_ms;
            waits.push(retry.delay_ms);
            fetch = retry;
        }
        assert_eq!(
            waits,
            [
                1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000, 256_000, 300_000,
                300_000, 300_000
            ]
        );
        assert!(!on(&chat, V1_SEND));
        assert_eq!(retry_delay_ms(40, FEATURES_REFRESH_MS), FEATURES_REFRESH_MS);
        assert_eq!(retry_delay_ms(3, 500), 500, "never more than the refresh");
    }

    #[test]
    fn a_retry_that_succeeds_turns_the_flags_on() {
        let mut requests = Requests::default();
        let chat = chat();
        let fetch = start(&mut requests, &chat, 0);
        let retry = requests.complete(fetch.id, 0, b"", 2_000).unwrap();
        assert!(!on(&chat, V1_SEND));
        let refresh = requests.complete(retry.id, 200, V1_ON, 3_500).unwrap();
        assert!(on(&chat, V1_SEND));
        assert_eq!(refresh.delay_ms, FEATURES_REFRESH_MS);
    }

    #[test]
    fn a_chat_created_while_a_retry_waits_takes_its_answer() {
        let mut requests = Requests::default();
        let first = chat();
        let fetch = start(&mut requests, &first, 0);
        let retry = requests.complete(fetch.id, 500, b"", 100).unwrap();
        let later = chat();
        assert_eq!(
            join(&mut requests, &later, 600),
            None,
            "it waits for the retry"
        );
        requests.complete(retry.id, 200, V1_ON, 1_500);
        assert!(on(&first, V1_SEND));
        assert!(on(&later, V1_SEND));
    }

    #[test]
    fn reads_stop_once_no_chat_waits() {
        let mut requests = Requests::default();
        let dropped = chat();
        let fetch = start(&mut requests, &dropped, 0);
        drop(dropped);
        assert_eq!(requests.complete(fetch.id, 503, b"", 10), None);
        assert!(requests.by_url.is_empty());

        let dropped = chat();
        let fetch = start(&mut requests, &dropped, 20);
        let refresh = requests.complete(fetch.id, 200, V1_ON, 30).unwrap();
        drop(dropped);
        assert_eq!(
            requests.complete(refresh.id, 200, V1_ON, 30 + FEATURES_REFRESH_MS + 100),
            None,
            "no refresh once the chat is gone"
        );
        assert!(requests.by_url.is_empty());
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
    fn an_answer_after_the_deadline_is_a_failed_read() {
        let mut requests = Requests::default();
        let chat = chat();
        let fetch = start(&mut requests, &chat, 0);
        let retry = requests.complete(fetch.id, 200, V1_ON, 2_000);
        assert!(!on(&chat, V1_SEND));
        assert_eq!(retry.map(|r| r.delay_ms), Some(RETRY_FIRST_DELAY_MS));
    }

    #[test]
    fn a_get_past_its_deadline_takes_no_more_chats() {
        let mut requests = Requests::default();
        let waiting = chat();
        let stuck = start(&mut requests, &waiting, 0);
        let late = chat();
        let fetch = start(&mut requests, &late, 2_000);
        assert_ne!(fetch.id, stuck.id, "a new GET");
        assert_eq!(requests.complete(stuck.id, 200, V1_ON, 2_100), None);
        assert!(
            !on(&late, V1_SEND) && !on(&waiting, V1_SEND),
            "the old GET's result is for no GET in flight"
        );
        requests.complete(fetch.id, 200, V1_ON, 2_200);
        assert!(on(&late, V1_SEND));
        assert!(
            on(&waiting, V1_SEND),
            "the new GET answers the old one's chats"
        );
    }

    #[test]
    fn a_get_that_replaces_a_stuck_refresh_keeps_its_answer() {
        let mut requests = Requests::default();
        let first = chat();
        let fetch = start(&mut requests, &first, 0);
        let refresh = requests.complete(fetch.id, 200, V1_ON, 10).unwrap();
        let past = 10 + refresh.delay_ms + refresh.timeout_ms;
        let late = chat();
        let replacement = start(&mut requests, &late, past);
        assert!(on(&late, V1_SEND), "the latest answer carries over");
        let retry = requests
            .complete(replacement.id, 503, b"", past + 100)
            .unwrap();
        assert!(on(&first, V1_SEND) && on(&late, V1_SEND));
        assert_eq!(retry.delay_ms, RETRY_FIRST_DELAY_MS);
    }

    #[test]
    fn the_chats_of_a_get_past_its_deadline_are_retried_with_the_new_one() {
        let mut requests = Requests::default();
        let waiting = chat();
        let first = start(&mut requests, &waiting, 0);
        let retry = requests.complete(first.id, 503, b"", 10).expect("a retry");
        let late = chat();
        let fetch = start(&mut requests, &late, 10 + retry.delay_ms + retry.timeout_ms);
        assert_eq!(requests.complete(retry.id, 0, b"", 4_000), None);
        let next = requests
            .complete(fetch.id, 503, b"", 4_100)
            .expect("the new GET's retry");
        requests.complete(next.id, 200, V1_ON, 4_100 + next.delay_ms);
        assert!(on(&late, V1_SEND));
        assert!(
            on(&waiting, V1_SEND),
            "the retry answers the old GET's chats"
        );
    }

    #[test]
    fn a_get_that_cannot_start_leaves_the_next_chat_its_own() {
        let mut requests = Requests::default();
        let stranded = chat();
        let fetch = start(&mut requests, &stranded, 0);
        requests.abandon(fetch.id);
        let next = chat();
        let own = start(&mut requests, &next, 10);
        assert_ne!(own.id, fetch.id);
        assert_eq!(own.delay_ms, 0, "a first read, not a retry");
        assert_eq!(requests.complete(fetch.id, 200, V1_ON, 20), None);
        requests.complete(own.id, 200, V1_ON, 30);
        assert!(on(&next, V1_SEND));
        assert!(
            on(&stranded, V1_SEND),
            "the next GET answers the stranded chat"
        );
    }

    #[test]
    fn a_get_that_cannot_start_schedules_no_retry() {
        let mut requests = Requests::default();
        let stranded = chat();
        let fetch = start(&mut requests, &stranded, 0);
        requests.abandon(fetch.id);
        assert_eq!(requests.complete(fetch.id, 0, b"", 10), None);
        assert_eq!(requests.complete(0, 200, V1_ON, 10), None);
        assert!(!on(&stranded, V1_SEND));
    }

    #[test]
    fn an_unknown_or_repeated_result_changes_nothing() {
        let mut requests = Requests::default();
        let chat = chat();
        let fetch = start(&mut requests, &chat, 0);
        assert_eq!(requests.complete(fetch.id + 100, 200, V1_ON, 10), None);
        assert!(!on(&chat, V1_SEND));
        assert!(requests.complete(fetch.id, 200, V1_ON, 20).is_some());
        assert!(on(&chat, V1_SEND));
        assert_eq!(requests.complete(fetch.id, 200, V1_OFF, 30), None);
        assert!(on(&chat, V1_SEND), "the GET already completed");
    }

    #[test]
    fn a_chat_that_joins_again_waits_once() {
        let mut requests = Requests::default();
        let kept = chat();
        let gone = chat();
        start(&mut requests, &kept, 0);
        assert_eq!(join(&mut requests, &gone, 1), None);
        drop(gone);
        assert_eq!(join(&mut requests, &kept, 2), None);
        assert_eq!(join(&mut requests, &kept, 3), None);
        assert_eq!(requests.by_url[URL].chats.len(), 1);
    }

    #[test]
    fn a_dropped_chat_is_skipped() {
        let mut requests = Requests::default();
        let dropped = chat();
        let fetch = start(&mut requests, &dropped, 0);
        let kept = chat();
        assert_eq!(join(&mut requests, &kept, 1), None);
        drop(dropped);
        requests.complete(fetch.id, 200, V1_ON, 10);
        assert!(on(&kept, V1_SEND));
    }

    #[test]
    #[cfg(feature = "bindings")]
    fn a_chat_reads_its_senders_bucket_once_it_has_an_identity() {
        let endpoint = "https://features.test/a_chat_reads_its_senders_bucket";
        let mut features = ChatFeatures::default();
        features.configure(endpoint, 30_000, 60_000);
        let first = features.start(None).expect("a read");
        assert_eq!(
            (first.url.as_str(), first.timeout_ms),
            (endpoint, 30_000),
            "no identity: no bucket"
        );
        assert_eq!(features.start(None), None, "one read per URL");
        assert!(shared::complete_fetch(first.id, 200, V1_ON).is_some());
        assert!(features.enabled(V1_SEND));

        let bucketed = features
            .start(Some("1234561001"))
            .expect("its bucket's read");
        assert_eq!(bucketed.url, format!("{endpoint}?bucket=1001"));
        assert!(!features.enabled(V1_SEND), "off until its bucket answers");
        assert_eq!(features.start(Some("9991001")), None, "the same bucket");
        let refresh = shared::complete_fetch(bucketed.id, 200, V1_ON).unwrap();
        assert!(features.enabled(V1_SEND));
        assert_eq!(refresh.delay_ms, 60_000);

        features.answer(200, V1_OFF);
        assert!(
            features.enabled(V1_SEND),
            "a chat that reads its own takes no caller's answer"
        );
    }

    #[test]
    #[cfg(feature = "bindings")]
    fn the_same_identity_again_restarts_a_read_its_binding_abandoned() {
        let endpoint = "https://features.test/the_same_identity_again";
        let mut features = ChatFeatures::default();
        features.configure(endpoint, 30_000, 60_000);
        let abandoned = features.start(Some("1001")).expect("a read");
        shared::abandon_fetch(abandoned.id);
        let again = features.start(Some("1001")).expect("a new read");
        assert_eq!(again.url, abandoned.url);
        assert!(shared::complete_fetch(again.id, 200, V1_ON).is_some());
        assert!(features.enabled(V1_SEND));
        assert_eq!(features.start(Some("1001")), None, "its read is live");
    }

    #[test]
    #[cfg(not(feature = "bindings"))]
    fn without_the_bindings_a_chat_reads_nothing() {
        let mut features = ChatFeatures::default();
        assert_eq!(features.start(Some("1001")), None);
        assert!(!features.enabled(V1_SEND));
    }

    #[test]
    fn a_caller_hands_over_each_answer() {
        let mut features = ChatFeatures::default();
        features.answer(503, V1_ON);
        assert!(!features.enabled(V1_SEND), "no answer");
        features.answer(200, V1_ON);
        assert!(features.enabled(V1_SEND));
        features.answer(500, b"");
        assert!(features.enabled(V1_SEND), "a failed read changes nothing");
        features.answer(200, V1_OFF);
        assert!(
            !features.enabled(V1_SEND),
            "each answer replaces the one before"
        );
    }
}
