//! Feature switches for this repository's language bindings.
//!
//! Not part of the public API. A chat reads `GET /2/chat/features` once, when
//! it is created, and keeps the answer for its lifetime (see
//! `crate::features`). The core decides what to fetch and what an answer
//! means; a binding only performs the GET, with its own HTTP stack. Its chat
//! constructor calls [`FeatureSwitches::start_features`], performs the GET it
//! returns, if any, in the background, and reports the result with
//! [`complete_fetch`].

pub use crate::features::Fetch;

use crate::features::shared;

/// Register the millisecond clock the core times GETs by. Only WebAssembly
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

/// For this repository's tests: the endpoint of every chat that does not set
/// its own, or the X API's when `None`.
pub fn set_default_endpoint(endpoint: Option<&str>) {
    shared::set_default_endpoint(endpoint);
}

/// A chat's part in the feature switches, as the bindings drive it.
pub trait FeatureSwitches {
    /// For this repository's tests: read this chat's switches from
    /// `endpoint`, within `timeout_ms`. Only a read started after this call
    /// uses them.
    fn configure_features(&self, endpoint: &str, timeout_ms: u64);

    /// Start this chat's one read of the switches: the GET to perform, or
    /// `None` when the chat takes the answer of a GET already in flight or
    /// has started its read already.
    fn start_features(&self) -> Option<Fetch>;
}

impl FeatureSwitches for crate::ChatCore {
    fn configure_features(&self, endpoint: &str, timeout_ms: u64) {
        crate::ChatCore::configure_features(self, endpoint, timeout_ms);
    }

    fn start_features(&self) -> Option<Fetch> {
        crate::ChatCore::start_features(self)
    }
}

#[cfg(feature = "juicebox")]
impl FeatureSwitches for crate::Chat {
    fn configure_features(&self, endpoint: &str, timeout_ms: u64) {
        FeatureSwitches::configure_features(self.core(), endpoint, timeout_ms);
    }

    fn start_features(&self) -> Option<Fetch> {
        FeatureSwitches::start_features(self.core())
    }
}
