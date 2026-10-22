//! Feature switches for this repository's language bindings.
//!
//! Not part of the public API. The core decides when `GET /2/chat/features`
//! is fetched and what an answer means (see `crate::features`); a binding only
//! performs the GETs, with its own HTTP stack. It registers a waker, which the
//! core calls on the thread of the send that first needs a fetch. The waker
//! starts a driver: a thread (or task) that takes each GET from the core,
//! performs it, and reports the result with [`complete_fetch`]. The driver
//! ends when the core says no chat needs the switches; the next send that
//! needs them wakes a new one.
//!
//! A driver either blocks in [`next_fetch`] (register it with [`set_waker`])
//! or polls with [`poll_fetch`] and waits on a timer of its own (register it
//! with [`set_polling_waker`]). A driver must poll when its thread cannot
//! wait inside the core, as in WebAssembly, or in Python, where a daemon
//! thread taking the interpreter lock back from native code during shutdown
//! is ended in a way that native frames cannot unwind.

pub use crate::features::{Fetch, Poll};

use crate::features::{shared, Timings};

/// Register the function that starts a driver blocking in [`next_fetch`].
/// The core calls it, without holding any lock, from inside the send that
/// needs the driver, so it must return promptly: start the driver and nothing
/// else.
pub fn set_waker(waker: fn()) {
    shared::set_waker(waker, shared::Driver::Blocking);
}

/// Register the function that starts or wakes a driver polling with
/// [`poll_fetch`]. The core calls it, without holding any lock, whenever the
/// plan changes: from inside a send, from [`complete_fetch`], and when a chat
/// leaves. It must return promptly: start the driver if none runs, or have it
/// poll again, and nothing else.
pub fn set_polling_waker(waker: fn()) {
    shared::set_waker(waker, shared::Driver::Polling);
}

/// The next GET to perform, waiting until one is due; `None` once no chat
/// needs the switches, and the driver then ends. Each GET runs concurrently
/// with the next call: the core enforces each one's deadline itself.
#[cfg(not(target_arch = "wasm32"))]
pub fn next_fetch() -> Option<Fetch> {
    shared::next_fetch()
}

/// The next step of a driver that cannot block, as in WebAssembly: a GET to
/// perform, how long to wait before polling again (unless woken first), or
/// [`Poll::Idle`] when no chat needs the switches.
pub fn poll_fetch() -> Poll {
    shared::poll_fetch()
}

/// Register the millisecond clock the core schedules by. Only WebAssembly
/// needs one: it has no system clock.
pub fn set_clock(clock: fn() -> u64) {
    shared::set_clock(clock);
}

/// Report the result of the GET `id`: its HTTP status, 0 when no response
/// arrived, and the body, read to its end or to [`Fetch::max_bytes`] plus one
/// byte, whichever comes first. A request that ended any other way reports
/// status 0.
pub fn complete_fetch(id: u64, status: u16, body: &[u8]) {
    shared::complete_fetch(id, status, body);
}

/// For this repository's tests: the endpoint of every chat that does not
/// set its own, or the X API's when `None`.
pub fn set_default_endpoint(endpoint: Option<&str>) {
    shared::set_default_endpoint(endpoint);
}

/// A chat's part in the feature switches, as the bindings drive it.
pub trait FeatureSwitches {
    /// For this repository's tests: fetch this chat's switches from
    /// `endpoint`, with these timings.
    fn configure_features(
        &self,
        endpoint: &str,
        timeout_ms: u64,
        recheck_ms: u64,
        first_retry_ms: u64,
    );

    /// Stop taking part in the feature-switch fetch. The switches keep the
    /// values they have now.
    fn release_features(&self);
}

impl FeatureSwitches for crate::ChatCore {
    fn configure_features(
        &self,
        endpoint: &str,
        timeout_ms: u64,
        recheck_ms: u64,
        first_retry_ms: u64,
    ) {
        let timings = Timings {
            timeout_ms,
            recheck_ms,
            first_retry_ms,
        };
        crate::ChatCore::configure_features(self, endpoint, timings);
    }

    fn release_features(&self) {
        crate::ChatCore::release_features(self);
    }
}

#[cfg(feature = "juicebox")]
impl FeatureSwitches for crate::Chat {
    fn configure_features(
        &self,
        endpoint: &str,
        timeout_ms: u64,
        recheck_ms: u64,
        first_retry_ms: u64,
    ) {
        FeatureSwitches::configure_features(
            self.core(),
            endpoint,
            timeout_ms,
            recheck_ms,
            first_retry_ms,
        );
    }

    fn release_features(&self) {
        FeatureSwitches::release_features(self.core());
    }
}
