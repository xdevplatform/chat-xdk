//! The millisecond clock the core times its waits by: how long until the
//! feature switches are read again, and how long a public-key lookup that
//! found nothing is remembered.

use std::sync::{PoisonError, RwLock};

static CLOCK: RwLock<Option<fn() -> u64>> = RwLock::new(None);

/// Milliseconds on the registered clock, else on a monotonic system clock.
/// WebAssembly has no system clock, so its binding registers one; without
/// one, time there stands still at zero.
pub(crate) fn now_ms() -> u64 {
    if let Some(clock) = *CLOCK.read().unwrap_or_else(PoisonError::into_inner) {
        return clock();
    }
    system_ms()
}

#[cfg(not(target_arch = "wasm32"))]
fn system_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let elapsed = START.get_or_init(std::time::Instant::now).elapsed();
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(target_arch = "wasm32")]
fn system_ms() -> u64 {
    0
}

/// Register the clock [`now_ms`] reads.
#[cfg_attr(not(feature = "bindings"), allow(dead_code))]
pub(crate) fn set_clock(clock: fn() -> u64) {
    *CLOCK.write().unwrap_or_else(PoisonError::into_inner) = Some(clock);
}
