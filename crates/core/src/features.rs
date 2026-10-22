//! Feature switches served by `GET /2/chat/features`.
//!
//! Internal: none of this is public API. The endpoint answers a flat map of
//! booleans, `{"features": {"v1_send": true}}`, each flag backed by its own
//! server-side decider and evaluated for the request's `bucket`, a number
//! derived from the identity public key.
//!
//! This module holds the whole policy: when to fetch, how chats share and
//! cache answers, retries, re-checks, response validation and the fail-closed
//! default. It never performs a request. In this repository's language
//! bindings a driver runs the GETs it hands out (see `crate::bindings`), each
//! with the binding's own HTTP stack; anywhere else no request is made and
//! every flag reads off.
//!
//! Chats in one process share one schedule per endpoint and bucket. A chat
//! asks for the flags on its first send, never earlier:
//!
//! - The first ask fetches at once. A failed fetch is retried after 1 s, then
//!   after twice the previous delay, up to the re-check interval (300 s).
//! - Each answer is re-checked once it is as old as the re-check interval.
//! - A chat takes the latest answer at the first send that finds one younger
//!   than the re-check interval; until then every flag reads off for it. From
//!   then on a flag stays on for the chat only while every later answer turns
//!   it on: a running chat sees a flag turn off within one re-check, and sees
//!   one turn on only as a new chat.
//! - Once no chat asks for an endpoint and bucket, its schedule stops. Its
//!   answer still serves a new chat until it is as old as the re-check
//!   interval.
//!
//! Every flag is off until an answer turns it on. A request that fails, takes
//! longer than its timeout (2 s), answers a status other than 200 or a body
//! over 64 KiB, or whose body is not a JSON object with a `features` object,
//! changes nothing. A flag whose value is not a boolean reads off.

// Without the bindings that run the fetches, the schedule is never used.
#![cfg_attr(not(feature = "bindings"), allow(dead_code))]

use std::collections::{HashMap, HashSet};

use crate::error::SdkError;

/// The flag that switches sends from the v0 wire format (0.5.x: contents under
/// the conversation key) to v1 (per-message keys).
pub const V1_SEND: &str = "v1_send";

/// URL of the feature-switch endpoint.
pub const FEATURES_ENDPOINT: &str = "https://api.x.com/2/chat/features";

/// Number of buckets the server's decider evaluates (availability 0–10000).
const BUCKETS: u64 = 10_000;

/// Largest response body accepted, in bytes.
const MAX_BODY: usize = 64 * 1024;

/// Requests in flight at once, across every endpoint and bucket.
const MAX_IN_FLIGHT: usize = 4;

/// The timeout of a request, the re-check interval and the first retry delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Timings {
    /// How long a request may take, body included.
    pub(crate) timeout_ms: u64,
    /// The age at which an answer is re-checked and stops serving new chats;
    /// also the longest retry delay.
    pub(crate) recheck_ms: u64,
    /// The delay before the first retry of a failed request.
    pub(crate) first_retry_ms: u64,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            timeout_ms: 2_000,
            recheck_ms: 300_000,
            first_retry_ms: 1_000,
        }
    }
}

/// A GET for a language binding to perform.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Fetch {
    /// Identifies the request when its result is reported.
    pub id: u64,
    /// The full URL, `bucket` query parameter included.
    pub url: String,
    /// The request must end within this time, body included.
    pub timeout_ms: u64,
    /// The largest body accepted: read at most one byte more, so a longer
    /// body is seen and rejected.
    pub max_bytes: usize,
}

/// What a driver does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poll {
    /// Perform this GET and report its result.
    Fetch(Fetch),
    /// Ask again after this many milliseconds, or when woken.
    Wait(u64),
    /// No chat needs the flags: the driver ends, and the next send that needs
    /// them wakes a new one.
    Idle,
}

/// What a change asks of the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Wake {
    /// Nothing.
    None,
    /// The running driver must plan again.
    Notify,
    /// No driver is running and one must start.
    Start,
}

/// One endpoint and bucket: the unit of sharing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Target {
    endpoint: String,
    bucket: u16,
}

impl Target {
    fn url(&self) -> String {
        let separator = if self.endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        format!("{}{separator}bucket={}", self.endpoint, self.bucket)
    }
}

/// The answer a chat took, by its generation.
#[derive(Debug, Clone)]
struct Capture {
    generation: u64,
    on: HashSet<String>,
}

/// The shared schedule and latest answer of one endpoint and bucket.
#[derive(Debug)]
struct Entry {
    timings: Timings,
    /// Chats asking for this endpoint and bucket.
    subscribers: usize,
    /// Number of answers so far; the latest answer's generation.
    generation: u64,
    /// The flags the latest answer turns on.
    on: HashSet<String>,
    /// For each flag any answer turned on, the generation of the latest
    /// answer that left it off (0 when none did).
    last_off: HashMap<String, u64>,
    answered_at: Option<u64>,
    next_fetch_at: u64,
    retry_ms: u64,
    /// The request in flight, as (id, deadline).
    in_flight: Option<(u64, u64)>,
}

impl Entry {
    fn new(timings: Timings, now: u64) -> Self {
        Self {
            timings,
            subscribers: 0,
            generation: 0,
            on: HashSet::new(),
            last_off: HashMap::new(),
            answered_at: None,
            next_fetch_at: now,
            retry_ms: timings.first_retry_ms,
            in_flight: None,
        }
    }

    /// Whether the latest answer is younger than the re-check interval.
    fn fresh(&self, now: u64) -> bool {
        self.answered_at
            .is_some_and(|at| now < at.saturating_add(self.timings.recheck_ms))
    }

    fn in_flight_until(&self, now: u64) -> bool {
        self.in_flight.is_some_and(|(_, deadline)| now < deadline)
    }

    fn answer(&mut self, flags: HashMap<String, bool>, now: u64) {
        self.generation += 1;
        let on: HashSet<String> = flags
            .into_iter()
            .filter_map(|(name, enabled)| enabled.then_some(name))
            .collect();
        for (name, last_off) in &mut self.last_off {
            if !on.contains(name) {
                *last_off = self.generation;
            }
        }
        for name in &on {
            self.last_off.entry(name.clone()).or_insert(0);
        }
        self.on = on;
        self.answered_at = Some(now);
        self.next_fetch_at = now.saturating_add(self.timings.recheck_ms);
        self.retry_ms = self.timings.first_retry_ms;
    }

    fn fail(&mut self, now: u64) {
        self.next_fetch_at = now.saturating_add(self.retry_ms);
        self.retry_ms = self
            .retry_ms
            .saturating_mul(2)
            .min(self.timings.recheck_ms.max(self.timings.first_retry_ms));
    }
}

/// Every endpoint and bucket chats ask for, and whether a driver runs.
#[derive(Debug, Default)]
struct Scheduler {
    entries: HashMap<Target, Entry>,
    last_id: u64,
    driver_running: bool,
}

impl Scheduler {
    /// Count a chat in for `target`, starting its schedule if no chat asked
    /// for it. A driver is started only when `can_start`: one is registered.
    fn subscribe(&mut self, target: &Target, timings: Timings, now: u64, can_start: bool) -> Wake {
        self.purge(now);
        let entry = self
            .entries
            .entry(target.clone())
            .or_insert_with(|| Entry::new(timings, now));
        entry.subscribers += 1;
        if entry.subscribers > 1 {
            Wake::None
        } else if self.driver_running {
            Wake::Notify
        } else if can_start {
            self.driver_running = true;
            Wake::Start
        } else {
            Wake::None
        }
    }

    fn unsubscribe(&mut self, target: &Target) -> Wake {
        match self.entries.get_mut(target) {
            Some(entry) if entry.subscribers > 0 => {
                entry.subscribers -= 1;
                if entry.subscribers == 0 && self.driver_running {
                    Wake::Notify
                } else {
                    Wake::None
                }
            }
            _ => Wake::None,
        }
    }

    /// The latest answer for `target`, if it is fresh enough to take.
    fn capture(&self, target: &Target, now: u64) -> Option<Capture> {
        let entry = self.entries.get(target)?;
        entry.fresh(now).then(|| Capture {
            generation: entry.generation,
            on: entry.on.clone(),
        })
    }

    /// Whether `name` is on for a chat that took `capture`: it was on then,
    /// and no answer since left it off.
    fn is_on(&self, target: &Target, capture: &Capture, name: &str) -> bool {
        capture.on.contains(name)
            && self.entries.get(target).is_some_and(|entry| {
                entry
                    .last_off
                    .get(name)
                    .is_some_and(|&off| off < capture.generation)
            })
    }

    /// Drop what no chat asks for and nothing can still use: no request in
    /// flight and no fresh answer.
    fn purge(&mut self, now: u64) {
        self.entries.retain(|_, entry| {
            entry.subscribers > 0 || entry.in_flight_until(now) || entry.fresh(now)
        });
    }

    fn poll(&mut self, now: u64) -> Poll {
        for entry in self.entries.values_mut() {
            if entry.in_flight.is_some() && !entry.in_flight_until(now) {
                entry.in_flight = None;
                entry.fail(now);
            }
        }
        self.purge(now);
        if !self.entries.values().any(|entry| entry.subscribers > 0) {
            self.driver_running = false;
            return Poll::Idle;
        }

        let in_flight = self
            .entries
            .values()
            .filter(|entry| entry.in_flight.is_some())
            .count();
        let room = in_flight < MAX_IN_FLIGHT;
        if room {
            let due = self
                .entries
                .iter()
                .filter(|(_, entry)| {
                    entry.subscribers > 0 && entry.in_flight.is_none() && entry.next_fetch_at <= now
                })
                .min_by_key(|(_, entry)| entry.next_fetch_at)
                .map(|(target, _)| target.clone());
            if let Some(target) = due {
                self.last_id += 1;
                let id = self.last_id;
                if let Some(entry) = self.entries.get_mut(&target) {
                    entry.in_flight = Some((id, now.saturating_add(entry.timings.timeout_ms)));
                    return Poll::Fetch(Fetch {
                        id,
                        url: target.url(),
                        timeout_ms: entry.timings.timeout_ms,
                        max_bytes: MAX_BODY,
                    });
                }
            }
        }

        let next = self
            .entries
            .values()
            .filter_map(|entry| match entry.in_flight {
                Some((_, deadline)) => Some(deadline),
                None if entry.subscribers > 0 && room => Some(entry.next_fetch_at),
                None => None,
            })
            .min()
            .unwrap_or(now);
        Poll::Wait(next.saturating_sub(now).max(1))
    }

    /// Apply the result of the request `id`. A result for no request in
    /// flight, or one that arrives after the request's deadline, changes no
    /// flag.
    fn complete(&mut self, id: u64, status: u16, body: &[u8], now: u64) -> Wake {
        let Some(entry) = self.entries.values_mut().find(|entry| {
            entry
                .in_flight
                .is_some_and(|(in_flight, _)| in_flight == id)
        }) else {
            return Wake::None;
        };
        let on_time = entry.in_flight_until(now);
        entry.in_flight = None;
        match parse_answer(status, body).filter(|_| on_time) {
            Some(flags) => entry.answer(flags, now),
            None => entry.fail(now),
        }
        if self.driver_running {
            Wake::Notify
        } else {
            Wake::None
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

/// The bucket (0–9999) for the identity public key in SPKI encoding: the
/// first 8 bytes of its SHA-256, big-endian, top bit cleared, modulo 10000.
/// The server evaluates each flag's decider for this bucket exactly as the
/// backend decider evaluates a user id.
pub(crate) fn bucket_for_public_key(spki: &[u8]) -> u16 {
    let digest = crate::crypto::hash::sha256(spki);
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    let id = u64::from_be_bytes(prefix) & (u64::MAX >> 1);
    // The modulus keeps the value below 10000, so it fits in u16.
    (id % BUCKETS) as u16
}

/// The feature switches of one chat.
#[derive(Debug, Default)]
pub(crate) struct ChatFeatures {
    /// The endpoint this chat asks; the process default when unset.
    endpoint: Option<String>,
    timings: Timings,
    subscription: Option<Subscription>,
    /// Set once the chat leaves the schedule: the flags on for it then.
    released: Option<HashSet<String>>,
    #[cfg(test)]
    forced: Option<HashSet<String>>,
}

/// The endpoint and bucket a chat asks for, and the answer it took.
#[derive(Debug)]
struct Subscription {
    target: Target,
    capture: Option<Capture>,
}

impl ChatFeatures {
    /// Whether the flag `name` is on for this chat, whose identity key has
    /// `bucket` (`None` without keys), and what the driver must do. This is
    /// the chat asking for the flags: it joins the schedule for its endpoint
    /// and bucket, which fetches if no answer is at hand.
    pub(crate) fn enabled(&mut self, bucket: Option<u16>, name: &str) -> (bool, Wake) {
        #[cfg(test)]
        if let Some(forced) = &self.forced {
            return (forced.contains(name), Wake::None);
        }
        if let Some(released) = &self.released {
            return (released.contains(name), Wake::None);
        }
        #[cfg(feature = "bindings")]
        if let Some(bucket) = bucket {
            return shared::enabled(self, bucket, name);
        }
        let _ = bucket;
        (false, Wake::None)
    }

    /// Ask `endpoint` from now on, with `timings`.
    pub(crate) fn configure(&mut self, endpoint: &str, timings: Timings) {
        self.endpoint = Some(endpoint.to_string());
        self.timings = timings;
    }

    /// Leave the schedule for good. The flags keep the values they have now.
    pub(crate) fn release(&mut self) -> Wake {
        if self.released.is_some() {
            return Wake::None;
        }
        #[cfg(feature = "bindings")]
        let (on, wake) = match self.subscription.take() {
            Some(subscription) => shared::leave(&subscription),
            None => (HashSet::new(), Wake::None),
        };
        #[cfg(not(feature = "bindings"))]
        let (on, wake) = (HashSet::new(), Wake::None);
        self.released = Some(on);
        wake
    }

    /// Read exactly `on` as on, bypassing the schedule.
    #[cfg(test)]
    pub(crate) fn force(&mut self, on: &[&str]) {
        self.forced = Some(on.iter().map(|name| name.to_string()).collect());
    }
}

impl Drop for ChatFeatures {
    fn drop(&mut self) {
        #[cfg(feature = "bindings")]
        if let Some(subscription) = self.subscription.take() {
            wake(shared::unsubscribe(&subscription.target));
        }
    }
}

/// Act on what a change asks of the driver: start one through the registered
/// waker, or get the running one to plan again.
pub(crate) fn wake(wake: Wake) {
    #[cfg(feature = "bindings")]
    shared::wake(wake);
    #[cfg(not(feature = "bindings"))]
    let _ = wake;
}

/// The schedule every chat in the process shares, and the driver interface
/// `crate::bindings` exposes.
#[cfg(feature = "bindings")]
pub(crate) mod shared {
    use std::collections::HashSet;
    use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError, RwLock};

    #[cfg(not(target_arch = "wasm32"))]
    use super::Fetch;
    use super::{ChatFeatures, Poll, Scheduler, Subscription, Target, Wake, FEATURES_ENDPOINT};

    /// How a registered driver waits for its next step.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Driver {
        /// Blocks in [`next_fetch`], which wakes it when the plan changes; the
        /// waker only starts one.
        Blocking,
        /// Polls with [`poll_fetch`] and waits on a timer of its own; the
        /// waker starts it or has it poll again.
        Polling,
    }

    /// The registered waker, and how its driver waits.
    #[derive(Clone, Copy)]
    struct Registered {
        waker: fn(),
        driver: Driver,
    }

    static WAKER: RwLock<Option<Registered>> = RwLock::new(None);
    static DEFAULT_ENDPOINT: RwLock<Option<String>> = RwLock::new(None);
    static CLOCK: RwLock<Option<fn() -> u64>> = RwLock::new(None);
    /// Signalled whenever the plan may have changed, waking a driver blocked in
    /// [`next_fetch`].
    #[cfg(not(target_arch = "wasm32"))]
    static PLAN: std::sync::Condvar = std::sync::Condvar::new();

    fn shared_scheduler() -> &'static Mutex<Scheduler> {
        static SCHEDULER: OnceLock<Mutex<Scheduler>> = OnceLock::new();
        SCHEDULER.get_or_init(Default::default)
    }

    fn scheduler() -> MutexGuard<'static, Scheduler> {
        shared_scheduler()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn registered() -> Option<Registered> {
        *WAKER.read().unwrap_or_else(PoisonError::into_inner)
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

    pub(crate) fn set_waker(waker: fn(), driver: Driver) {
        *WAKER.write().unwrap_or_else(PoisonError::into_inner) = Some(Registered { waker, driver });
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

    pub(super) fn wake(wake: Wake) {
        match (wake, registered()) {
            (Wake::None, _) | (_, None) => {}
            (
                Wake::Notify,
                Some(Registered {
                    driver: Driver::Blocking,
                    ..
                }),
            ) => {
                #[cfg(not(target_arch = "wasm32"))]
                PLAN.notify_all();
            }
            (_, Some(registered)) => (registered.waker)(),
        }
    }

    pub(super) fn enabled(features: &mut ChatFeatures, bucket: u16, name: &str) -> (bool, Wake) {
        let target = Target {
            endpoint: features.endpoint.clone().unwrap_or_else(default_endpoint),
            bucket,
        };
        let now = now_ms();
        let mut scheduler = scheduler();
        let mut wake = Wake::None;
        if features.subscription.as_ref().map(|s| &s.target) != Some(&target) {
            if let Some(old) = features.subscription.take() {
                wake = wake.max(scheduler.unsubscribe(&old.target));
            }
            wake = wake.max(scheduler.subscribe(
                &target,
                features.timings,
                now,
                registered().is_some(),
            ));
            features.subscription = Some(Subscription {
                target,
                capture: None,
            });
        }
        let Some(subscription) = features.subscription.as_mut() else {
            return (false, wake);
        };
        if subscription.capture.is_none() {
            subscription.capture = scheduler.capture(&subscription.target, now);
        }
        let on = subscription
            .capture
            .as_ref()
            .is_some_and(|capture| scheduler.is_on(&subscription.target, capture, name));
        (on, wake)
    }

    /// The flags on for `subscription` now, as it leaves the schedule.
    pub(super) fn leave(subscription: &Subscription) -> (HashSet<String>, Wake) {
        let mut scheduler = scheduler();
        let capture = subscription
            .capture
            .clone()
            .or_else(|| scheduler.capture(&subscription.target, now_ms()));
        let on = capture
            .as_ref()
            .map(|capture| {
                capture
                    .on
                    .iter()
                    .filter(|name| scheduler.is_on(&subscription.target, capture, name))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        (on, scheduler.unsubscribe(&subscription.target))
    }

    pub(super) fn unsubscribe(target: &Target) -> Wake {
        scheduler().unsubscribe(target)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn next_fetch() -> Option<Fetch> {
        drive(shared_scheduler(), &PLAN, now_ms)
    }

    /// Block until `scheduler` has a GET due, or return `None` once it is
    /// idle; `plan` is signalled whenever the schedule changes.
    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn drive(
        scheduler: &Mutex<Scheduler>,
        plan: &std::sync::Condvar,
        now: fn() -> u64,
    ) -> Option<Fetch> {
        let mut guard = scheduler.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            match guard.poll(now()) {
                Poll::Fetch(fetch) => return Some(fetch),
                Poll::Idle => return None,
                Poll::Wait(ms) => {
                    guard = plan
                        .wait_timeout(guard, std::time::Duration::from_millis(ms))
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            }
        }
    }

    pub(crate) fn poll_fetch() -> Poll {
        scheduler().poll(now_ms())
    }

    pub(crate) fn complete_fetch(id: u64, status: u16, body: &[u8]) {
        let change = scheduler().complete(id, status, body, now_ms());
        wake(change);
    }

    #[cfg(test)]
    pub(crate) fn subscribers(endpoint: &str, bucket: u16) -> usize {
        let target = Target {
            endpoint: endpoint.to_string(),
            bucket,
        };
        scheduler()
            .entries
            .get(&target)
            .map_or(0, |entry| entry.subscribers)
    }

    /// Answer the request in flight for `endpoint` and `bucket`, or fail it,
    /// as its driver would.
    #[cfg(test)]
    pub(crate) fn answer(endpoint: &str, bucket: u16, status: u16, body: &str) -> bool {
        let target = Target {
            endpoint: endpoint.to_string(),
            bucket,
        };
        let now = now_ms();
        let mut scheduler = scheduler();
        let Some(entry) = scheduler.entries.get_mut(&target) else {
            return false;
        };
        if entry.in_flight.is_none() {
            scheduler.last_id += 1;
            let id = scheduler.last_id;
            if let Some(entry) = scheduler.entries.get_mut(&target) {
                entry.in_flight = Some((id, now.saturating_add(entry.timings.timeout_ms)));
            }
        }
        let Some((id, _)) = scheduler.entries.get(&target).and_then(|e| e.in_flight) else {
            return false;
        };
        scheduler.complete(id, status, body.as_bytes(), now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINT: &str = "https://features.test/2/chat/features";

    fn target(bucket: u16) -> Target {
        Target {
            endpoint: ENDPOINT.to_string(),
            bucket,
        }
    }

    fn timings() -> Timings {
        Timings::default()
    }

    fn flags(json: &str) -> HashMap<String, bool> {
        parse_features(json).unwrap()
    }

    fn fetch(scheduler: &mut Scheduler, now: u64) -> Fetch {
        match scheduler.poll(now) {
            Poll::Fetch(fetch) => fetch,
            other => panic!("expected a fetch at {now}, got {other:?}"),
        }
    }

    fn ok(scheduler: &mut Scheduler, fetch: &Fetch, body: &str, now: u64) {
        scheduler.complete(fetch.id, 200, body.as_bytes(), now);
    }

    /// A chat that asks `target` at `now` through `scheduler`, as a send does.
    struct Chat {
        target: Target,
        capture: Option<Capture>,
    }

    impl Chat {
        fn join(scheduler: &mut Scheduler, target: Target, now: u64) -> (Self, Wake) {
            let wake = scheduler.subscribe(&target, timings(), now, true);
            (
                Self {
                    target,
                    capture: None,
                },
                wake,
            )
        }

        fn on(&mut self, scheduler: &Scheduler, name: &str, now: u64) -> bool {
            if self.capture.is_none() {
                self.capture = scheduler.capture(&self.target, now);
            }
            self.capture
                .as_ref()
                .is_some_and(|capture| scheduler.is_on(&self.target, capture, name))
        }
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
    fn nothing_is_fetched_before_a_chat_asks() {
        let mut scheduler = Scheduler::default();
        assert_eq!(scheduler.poll(0), Poll::Idle);
        assert_eq!(scheduler.poll(1_000_000), Poll::Idle);
        assert!(!scheduler.driver_running);
    }

    #[test]
    fn the_first_ask_starts_a_driver_and_fetches_at_once() {
        let mut scheduler = Scheduler::default();
        let (mut chat, wake) = Chat::join(&mut scheduler, target(7), 50);
        assert_eq!(wake, Wake::Start);
        assert!(!chat.on(&scheduler, V1_SEND, 50), "off until an answer");

        let fetch = fetch(&mut scheduler, 50);
        assert_eq!(fetch.url, format!("{ENDPOINT}?bucket=7"));
        assert_eq!(fetch.timeout_ms, 2_000);
        assert_eq!(fetch.max_bytes, 64 * 1024);
        assert_eq!(scheduler.poll(50), Poll::Wait(2_000), "until the deadline");

        ok(
            &mut scheduler,
            &fetch,
            r#"{"features":{"v1_send":true}}"#,
            300,
        );
        assert!(chat.on(&scheduler, V1_SEND, 300));
        assert!(!chat.on(&scheduler, "other", 300));
        assert_eq!(
            scheduler.poll(300),
            Poll::Wait(300_000),
            "until the re-check"
        );
    }

    #[test]
    fn the_url_keeps_an_existing_query() {
        let target = Target {
            endpoint: "http://127.0.0.1:9/features?x=1".to_string(),
            bucket: 42,
        };
        assert_eq!(target.url(), "http://127.0.0.1:9/features?x=1&bucket=42");
    }

    #[test]
    fn chats_asking_for_one_endpoint_and_bucket_share_one_request() {
        let mut scheduler = Scheduler::default();
        let (mut first, wake) = Chat::join(&mut scheduler, target(7), 0);
        assert_eq!(wake, Wake::Start);
        let request = fetch(&mut scheduler, 0);
        let mut others: Vec<Chat> = (0..9)
            .map(|_| {
                let (chat, wake) = Chat::join(&mut scheduler, target(7), 10);
                assert_eq!(wake, Wake::None, "already scheduled");
                chat
            })
            .collect();
        assert_eq!(scheduler.poll(10), Poll::Wait(1_990), "no second request");

        ok(
            &mut scheduler,
            &request,
            r#"{"features":{"v1_send":true}}"#,
            100,
        );
        assert!(first.on(&scheduler, V1_SEND, 100));
        assert!(others
            .iter_mut()
            .all(|chat| chat.on(&scheduler, V1_SEND, 100)));
        assert_eq!(scheduler.poll(100), Poll::Wait(300_000));
    }

    #[test]
    fn each_bucket_and_endpoint_has_its_own_schedule() {
        let mut scheduler = Scheduler::default();
        let other_endpoint = Target {
            endpoint: "https://elsewhere.test/features".to_string(),
            bucket: 7,
        };
        for target in [target(7), target(8), other_endpoint] {
            Chat::join(&mut scheduler, target, 0);
        }
        let urls: HashSet<String> = (0..3).map(|_| fetch(&mut scheduler, 0).url).collect();
        assert_eq!(urls.len(), 3);
    }

    #[test]
    fn a_later_chat_takes_a_fresh_answer_without_a_request() {
        let mut scheduler = Scheduler::default();
        let (_first, _) = Chat::join(&mut scheduler, target(7), 0);
        let request = fetch(&mut scheduler, 0);
        ok(
            &mut scheduler,
            &request,
            r#"{"features":{"v1_send":true}}"#,
            0,
        );

        let (mut second, wake) = Chat::join(&mut scheduler, target(7), 299_999);
        assert_eq!(wake, Wake::None);
        assert!(second.on(&scheduler, V1_SEND, 299_999));
        assert_eq!(scheduler.poll(299_999), Poll::Wait(1));
    }

    #[test]
    fn failures_back_off_from_one_second_to_the_recheck_interval() {
        let mut scheduler = Scheduler::default();
        let (mut chat, _) = Chat::join(&mut scheduler, target(7), 0);
        let mut now = 0;
        let mut delays = Vec::new();
        for _ in 0..12 {
            let request = fetch(&mut scheduler, now);
            scheduler.complete(request.id, 503, b"", now);
            let Poll::Wait(delay) = scheduler.poll(now) else {
                panic!("expected a wait");
            };
            delays.push(delay);
            now += delay;
        }
        assert_eq!(
            delays,
            [
                1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000, 256_000, 300_000,
                300_000, 300_000
            ]
        );
        assert!(!chat.on(&scheduler, V1_SEND, now));

        let request = fetch(&mut scheduler, now);
        ok(
            &mut scheduler,
            &request,
            r#"{"features":{"v1_send":true}}"#,
            now,
        );
        assert!(chat.on(&scheduler, V1_SEND, now));

        // A success resets the backoff: the next failure retries after 1 s.
        now += 300_000;
        let request = fetch(&mut scheduler, now);
        scheduler.complete(request.id, 500, b"", now);
        assert_eq!(scheduler.poll(now), Poll::Wait(1_000));
    }

    #[test]
    fn every_kind_of_failure_leaves_every_flag_off() {
        let oversized = format!(
            r#"{{"features":{{"v1_send":true}}}}{}"#,
            " ".repeat(64 * 1024)
        );
        let cases: Vec<(u16, Vec<u8>)> = vec![
            (0, br#"{"features":{"v1_send":true}}"#.to_vec()),
            (404, br#"{"features":{"v1_send":true}}"#.to_vec()),
            (500, br#"{"features":{"v1_send":true}}"#.to_vec()),
            (204, Vec::new()),
            (200, b"not json".to_vec()),
            (200, br#"{"v1_send":true}"#.to_vec()),
            (200, br#"{"features":{"v1_send":"true"}}"#.to_vec()),
            (200, b"{\"features\":{\"v1_send\":true}}\xff".to_vec()),
            (200, oversized.into_bytes()),
        ];
        for (status, body) in cases {
            let mut scheduler = Scheduler::default();
            let (mut chat, _) = Chat::join(&mut scheduler, target(7), 0);
            let request = fetch(&mut scheduler, 0);
            scheduler.complete(request.id, status, &body, 10);
            assert!(
                !chat.on(&scheduler, V1_SEND, 10),
                "{status} {} bytes",
                body.len()
            );
        }
    }

    #[test]
    fn a_body_exactly_at_the_limit_is_accepted() {
        let body = r#"{"features":{"v1_send":true}}"#;
        let padded = format!("{body}{}", " ".repeat(64 * 1024 - body.len()));
        let mut scheduler = Scheduler::default();
        let (mut chat, _) = Chat::join(&mut scheduler, target(7), 0);
        let request = fetch(&mut scheduler, 0);
        scheduler.complete(request.id, 200, padded.as_bytes(), 10);
        assert!(chat.on(&scheduler, V1_SEND, 10));
    }

    #[test]
    fn a_request_past_its_deadline_fails_and_its_late_answer_is_ignored() {
        let mut scheduler = Scheduler::default();
        let (mut chat, _) = Chat::join(&mut scheduler, target(7), 0);
        let request = fetch(&mut scheduler, 0);
        assert_eq!(scheduler.poll(1_999), Poll::Wait(1));
        assert_eq!(
            scheduler.poll(2_000),
            Poll::Wait(1_000),
            "timed out: retry after 1 s"
        );
        ok(
            &mut scheduler,
            &request,
            r#"{"features":{"v1_send":true}}"#,
            2_500,
        );
        assert!(!chat.on(&scheduler, V1_SEND, 2_500));

        // An answer that arrives after the deadline, before any poll noticed
        // it, fails the same way.
        let retry = fetch(&mut scheduler, 3_000);
        ok(
            &mut scheduler,
            &retry,
            r#"{"features":{"v1_send":true}}"#,
            5_000,
        );
        assert!(!chat.on(&scheduler, V1_SEND, 5_000));
        assert_eq!(scheduler.poll(5_000), Poll::Wait(2_000));
    }

    #[test]
    fn an_unknown_or_repeated_result_changes_nothing() {
        let mut scheduler = Scheduler::default();
        let (mut chat, _) = Chat::join(&mut scheduler, target(7), 0);
        let request = fetch(&mut scheduler, 0);
        scheduler.complete(
            request.id + 100,
            200,
            br#"{"features":{"v1_send":true}}"#,
            10,
        );
        assert!(!chat.on(&scheduler, V1_SEND, 10));
        ok(
            &mut scheduler,
            &request,
            r#"{"features":{"v1_send":true}}"#,
            20,
        );
        assert!(chat.on(&scheduler, V1_SEND, 20));
        ok(&mut scheduler, &request, r#"{"features":{}}"#, 30);
        assert!(
            chat.on(&scheduler, V1_SEND, 30),
            "the request already completed"
        );
    }

    #[test]
    fn a_recheck_turns_a_flag_off_for_running_chats_and_never_back_on() {
        let mut scheduler = Scheduler::default();
        let (mut chat, _) = Chat::join(&mut scheduler, target(7), 0);
        let request = fetch(&mut scheduler, 0);
        ok(
            &mut scheduler,
            &request,
            r#"{"features":{"v1_send":true,"a":true}}"#,
            0,
        );
        assert!(chat.on(&scheduler, V1_SEND, 0));

        let recheck = fetch(&mut scheduler, 300_000);
        ok(
            &mut scheduler,
            &recheck,
            r#"{"features":{"a":true}}"#,
            300_000,
        );
        assert!(!chat.on(&scheduler, V1_SEND, 300_000), "turned off");
        assert!(chat.on(&scheduler, "a", 300_000));

        let recheck = fetch(&mut scheduler, 600_000);
        ok(
            &mut scheduler,
            &recheck,
            r#"{"features":{"v1_send":true,"b":true}}"#,
            600_000,
        );
        assert!(!chat.on(&scheduler, V1_SEND, 600_000), "never back on");
        assert!(!chat.on(&scheduler, "a", 600_000), "a missing flag is off");
        assert!(
            !chat.on(&scheduler, "b", 600_000),
            "never a flag it did not take"
        );

        // A new chat takes the latest answer.
        let (mut later, _) = Chat::join(&mut scheduler, target(7), 600_001);
        assert!(later.on(&scheduler, V1_SEND, 600_001));
        assert!(later.on(&scheduler, "b", 600_001));
    }

    #[test]
    fn a_chat_that_asked_before_the_first_answer_takes_it() {
        let mut scheduler = Scheduler::default();
        let (mut chat, _) = Chat::join(&mut scheduler, target(7), 0);
        let request = fetch(&mut scheduler, 0);
        assert!(!chat.on(&scheduler, V1_SEND, 10));
        ok(
            &mut scheduler,
            &request,
            r#"{"features":{"v1_send":true}}"#,
            20,
        );
        assert!(chat.on(&scheduler, V1_SEND, 20));
    }

    #[test]
    fn a_failed_recheck_changes_nothing() {
        let mut scheduler = Scheduler::default();
        let (mut chat, _) = Chat::join(&mut scheduler, target(7), 0);
        let request = fetch(&mut scheduler, 0);
        ok(
            &mut scheduler,
            &request,
            r#"{"features":{"v1_send":true}}"#,
            0,
        );
        assert!(chat.on(&scheduler, V1_SEND, 0));
        let recheck = fetch(&mut scheduler, 300_000);
        scheduler.complete(recheck.id, 503, b"", 300_000);
        assert!(chat.on(&scheduler, V1_SEND, 300_000));
        assert_eq!(scheduler.poll(300_000), Poll::Wait(1_000));
    }

    #[test]
    fn a_stale_answer_serves_no_new_chat() {
        let mut scheduler = Scheduler::default();
        let (mut first, _) = Chat::join(&mut scheduler, target(7), 0);
        let request = fetch(&mut scheduler, 0);
        ok(
            &mut scheduler,
            &request,
            r#"{"features":{"v1_send":true}}"#,
            0,
        );
        assert!(first.on(&scheduler, V1_SEND, 0));
        let recheck = fetch(&mut scheduler, 300_000);
        scheduler.complete(recheck.id, 503, b"", 300_000);

        let (mut second, _) = Chat::join(&mut scheduler, target(7), 300_500);
        assert!(
            !second.on(&scheduler, V1_SEND, 300_500),
            "the answer is stale"
        );
        assert!(
            first.on(&scheduler, V1_SEND, 300_500),
            "the running chat keeps it"
        );
        let retry = fetch(&mut scheduler, 301_000);
        ok(
            &mut scheduler,
            &retry,
            r#"{"features":{"v1_send":true}}"#,
            301_000,
        );
        assert!(second.on(&scheduler, V1_SEND, 301_000));
    }

    #[test]
    fn the_schedule_stops_when_the_last_chat_leaves() {
        let mut scheduler = Scheduler::default();
        let (first, _) = Chat::join(&mut scheduler, target(7), 0);
        let (second, _) = Chat::join(&mut scheduler, target(7), 0);
        let request = fetch(&mut scheduler, 0);
        ok(
            &mut scheduler,
            &request,
            r#"{"features":{"v1_send":true}}"#,
            0,
        );

        assert_eq!(scheduler.unsubscribe(&first.target), Wake::None);
        assert_eq!(scheduler.poll(1), Poll::Wait(299_999));
        assert_eq!(scheduler.unsubscribe(&second.target), Wake::Notify);
        assert_eq!(scheduler.poll(2), Poll::Idle);
        assert!(!scheduler.driver_running);
        assert_eq!(scheduler.poll(300_000), Poll::Idle, "no re-check");
    }

    #[test]
    fn a_chat_returning_within_the_recheck_interval_resumes_the_cached_schedule() {
        let mut scheduler = Scheduler::default();
        let (first, _) = Chat::join(&mut scheduler, target(7), 0);
        let request = fetch(&mut scheduler, 0);
        ok(
            &mut scheduler,
            &request,
            r#"{"features":{"v1_send":true}}"#,
            0,
        );
        scheduler.unsubscribe(&first.target);
        assert_eq!(scheduler.poll(1), Poll::Idle);

        let (mut back, wake) = Chat::join(&mut scheduler, target(7), 100_000);
        assert_eq!(wake, Wake::Start, "the stopped driver starts again");
        assert!(back.on(&scheduler, V1_SEND, 100_000), "no request needed");
        assert_eq!(
            scheduler.poll(100_000),
            Poll::Wait(200_000),
            "the re-check stays due at 300 s"
        );
    }

    #[test]
    fn a_chat_returning_after_the_recheck_interval_fetches_again() {
        let mut scheduler = Scheduler::default();
        let (first, _) = Chat::join(&mut scheduler, target(7), 0);
        let request = fetch(&mut scheduler, 0);
        ok(
            &mut scheduler,
            &request,
            r#"{"features":{"v1_send":true}}"#,
            0,
        );
        scheduler.unsubscribe(&first.target);
        assert_eq!(scheduler.poll(1), Poll::Idle);

        let (mut back, _) = Chat::join(&mut scheduler, target(7), 300_000);
        assert!(
            !back.on(&scheduler, V1_SEND, 300_000),
            "the cached answer expired"
        );
        let again = fetch(&mut scheduler, 300_000);
        ok(
            &mut scheduler,
            &again,
            r#"{"features":{"v1_send":false}}"#,
            300_010,
        );
        assert!(!back.on(&scheduler, V1_SEND, 300_010));
    }

    #[test]
    fn a_request_in_flight_when_the_last_chat_leaves_serves_the_next_one() {
        let mut scheduler = Scheduler::default();
        let (first, _) = Chat::join(&mut scheduler, target(7), 0);
        let request = fetch(&mut scheduler, 0);
        scheduler.unsubscribe(&first.target);
        assert_eq!(scheduler.poll(10), Poll::Idle);

        let (mut next, _) = Chat::join(&mut scheduler, target(7), 20);
        assert_eq!(scheduler.poll(20), Poll::Wait(1_980), "no second request");
        ok(
            &mut scheduler,
            &request,
            r#"{"features":{"v1_send":true}}"#,
            30,
        );
        assert!(next.on(&scheduler, V1_SEND, 30));
    }

    #[test]
    fn a_driver_starts_only_when_none_runs_and_one_is_registered() {
        let mut scheduler = Scheduler::default();
        assert_eq!(
            scheduler.subscribe(&target(1), timings(), 0, false),
            Wake::None
        );
        assert!(!scheduler.driver_running, "no waker: nothing to start");
        assert_eq!(
            scheduler.subscribe(&target(2), timings(), 0, true),
            Wake::Start
        );
        assert_eq!(
            scheduler.subscribe(&target(3), timings(), 0, true),
            Wake::Notify
        );
        assert_eq!(
            scheduler.subscribe(&target(3), timings(), 0, true),
            Wake::None
        );
    }

    #[test]
    fn at_most_four_requests_are_in_flight() {
        let mut scheduler = Scheduler::default();
        for bucket in 0..6 {
            Chat::join(&mut scheduler, target(bucket), 0);
        }
        let first: Vec<Fetch> = (0..4).map(|_| fetch(&mut scheduler, 0)).collect();
        assert_eq!(
            scheduler.poll(0),
            Poll::Wait(2_000),
            "full: wait for a deadline"
        );
        ok(&mut scheduler, &first[0], r#"{"features":{}}"#, 5);
        let fifth = fetch(&mut scheduler, 5);
        assert_eq!(fifth.id, 5);
        assert_eq!(scheduler.poll(5), Poll::Wait(1_995));
        // At 2 s three requests time out, which makes room for the sixth.
        let sixth = fetch(&mut scheduler, 2_000);
        assert_eq!(sixth.id, 6);
        assert_ne!(sixth.url, fifth.url);
    }

    /// The blocking driver of the native bindings, against a schedule of its
    /// own: it sleeps while nothing is due, wakes when the plan changes, and
    /// returns once the last chat leaves.
    #[cfg(all(feature = "bindings", not(target_arch = "wasm32")))]
    #[test]
    fn a_blocked_driver_wakes_on_changes_and_ends_with_the_last_chat() {
        use std::sync::mpsc;
        use std::sync::{Arc, Condvar, Mutex};
        use std::time::Duration;

        fn clock() -> u64 {
            static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
            START
                .get_or_init(std::time::Instant::now)
                .elapsed()
                .as_millis() as u64
        }

        let schedule = Arc::new((Mutex::new(Scheduler::default()), Condvar::new()));
        let wake = schedule
            .0
            .lock()
            .unwrap()
            .subscribe(&target(7), timings(), clock(), true);
        assert_eq!(wake, Wake::Start);

        let (fetches, received) = mpsc::channel();
        let driver = {
            let schedule = Arc::clone(&schedule);
            std::thread::spawn(move || {
                while let Some(fetch) = shared::drive(&schedule.0, &schedule.1, clock) {
                    fetches.send(fetch).unwrap();
                }
            })
        };

        let first = received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(first.url, format!("{ENDPOINT}?bucket=7"));
        schedule.0.lock().unwrap().complete(
            first.id,
            200,
            br#"{"features":{"v1_send":true}}"#,
            clock(),
        );
        schedule.1.notify_all();

        // A second bucket wakes the sleeping driver at once.
        schedule
            .0
            .lock()
            .unwrap()
            .subscribe(&target(8), timings(), clock(), true);
        schedule.1.notify_all();
        let second = received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(second.url, format!("{ENDPOINT}?bucket=8"));
        schedule
            .0
            .lock()
            .unwrap()
            .complete(second.id, 503, b"", clock());

        for bucket in [7, 8] {
            schedule.0.lock().unwrap().unsubscribe(&target(bucket));
        }
        schedule.1.notify_all();
        let (done, ended) = mpsc::channel();
        std::thread::spawn(move || {
            driver.join().unwrap();
            done.send(()).unwrap();
        });
        ended
            .recv_timeout(Duration::from_secs(5))
            .expect("the driver returns once no chat is left");
        assert!(
            received.try_recv().is_err(),
            "no request after the last chat left"
        );
        assert!(!schedule.0.lock().unwrap().driver_running);
    }

    #[test]
    fn a_released_chat_keeps_its_flags_and_leaves_the_schedule() {
        let mut features = ChatFeatures::default();
        assert_eq!(features.release(), Wake::None);
        assert_eq!(features.enabled(Some(7), V1_SEND), (false, Wake::None));
    }

    #[test]
    fn the_bucket_is_the_reduced_sha256_prefix_of_the_key() {
        // SHA-256("") = e3b0c44298fc1c14...; the first 8 bytes with the top bit
        // cleared are 0x63b0c44298fc1c14 = 7183457195969485844.
        assert_eq!(bucket_for_public_key(b""), 5844);
        // SHA-256("abc") = ba7816bf8f01cfea...; with the top bit cleared,
        // 0x3a7816bf8f01cfea = 4213142463398924266.
        assert_eq!(bucket_for_public_key(b"abc"), 4266);
        for spki in [&b"x"[..], &[0u8; 91][..], &[0xffu8; 91][..]] {
            assert!(bucket_for_public_key(spki) < 10_000);
        }
    }
}
