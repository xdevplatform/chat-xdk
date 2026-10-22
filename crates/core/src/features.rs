//! Feature switches served by `GET /2/chat/features`.
//!
//! Internal: the language bindings fetch the endpoint themselves and apply the
//! response through `crate::bindings`; none of this is public API.
//!
//! The endpoint answers a flat map of booleans, `{"features": {"v1_send":
//! true}}`, each flag backed by its own server-side decider and evaluated for
//! the caller's bucket. A caller with keys loaded sends the bucket derived
//! from its identity public key; without keys it sends none and the server
//! buckets it by IP.
//!
//! Every flag is off until a response turns it on: a missing key, a non-boolean
//! value, a failed request, or no request at all all read as off. Unknown keys
//! are kept, so flags this SDK version attaches no behavior to can be read.

// Without the bindings that fetch them, the flags are never applied.
#![cfg_attr(not(feature = "bindings"), allow(dead_code))]

use std::collections::HashMap;

use crate::error::SdkError;

/// The flag that switches sends from the v0 wire format (0.5.x: contents under
/// the conversation key) to v1 (per-message keys).
pub const V1_SEND: &str = "v1_send";

/// Default URL of the feature-switch endpoint.
pub const FEATURES_ENDPOINT: &str = "https://api.x.com/2/chat/features";

/// Number of buckets the server's decider evaluates (availability 0–10000).
const BUCKETS: u64 = 10_000;

/// How a features response merges into the current flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureApply {
    /// Replace the flags with the response: the fetch when a chat is created
    /// and the re-fetch with the key's bucket once keys load.
    Full,
    /// Keep a flag on only while the response still turns it on, and never
    /// turn a flag on: the periodic re-check.
    DowngradeOnly,
}

/// Which bucket the server evaluated a response for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucketing {
    /// The bucket of the loaded identity public key.
    Key,
    /// No bucket was sent, so the server bucketed by the caller's IP.
    Ip,
}

/// Feature flags of one `ChatCore`.
#[derive(Debug, Default)]
pub(crate) struct FeatureState {
    flags: HashMap<String, bool>,
    bucketing: Option<Bucketing>,
}

impl FeatureState {
    /// Merge `flags` from a response to a request that carried a bucket
    /// (`bucketed`) or none.
    pub(crate) fn apply(
        &mut self,
        flags: HashMap<String, bool>,
        mode: FeatureApply,
        bucketed: bool,
    ) {
        match mode {
            FeatureApply::Full => {
                self.flags = flags;
                self.bucketing = Some(if bucketed {
                    Bucketing::Key
                } else {
                    Bucketing::Ip
                });
            }
            FeatureApply::DowngradeOnly => {
                for (name, enabled) in self.flags.iter_mut() {
                    *enabled = *enabled && flags.get(name) == Some(&true);
                }
            }
        }
    }

    /// Whether keys are loaded but no response to a request carrying their
    /// bucket has applied (none at all, or only an IP-bucketed one): the flags
    /// must be fetched with the key's bucket, and read off until they are.
    pub(crate) fn refetch_due(&self, has_keys: bool) -> bool {
        has_keys && self.bucketing != Some(Bucketing::Key)
    }

    pub(crate) fn is_enabled(&self, name: &str, has_keys: bool) -> bool {
        !self.refetch_due(has_keys) && self.flags.get(name) == Some(&true)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(json: &str) -> HashMap<String, bool> {
        parse_features(json).unwrap()
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
    fn every_flag_is_off_until_a_response_turns_it_on() {
        let state = FeatureState::default();
        assert!(!state.is_enabled(V1_SEND, false));
        assert!(!state.is_enabled(V1_SEND, true));
        assert!(!state.refetch_due(false));
        assert!(
            state.refetch_due(true),
            "keys without a key-bucketed response: a fetch is due"
        );
    }

    #[test]
    fn a_full_apply_replaces_the_flags() {
        let mut state = FeatureState::default();
        state.apply(
            flags(r#"{"features":{"v1_send":true,"later":true}}"#),
            FeatureApply::Full,
            true,
        );
        assert!(state.is_enabled(V1_SEND, true));
        assert!(state.is_enabled("later", true));
        assert!(!state.is_enabled("missing", true));

        state.apply(
            flags(r#"{"features":{"later":true}}"#),
            FeatureApply::Full,
            true,
        );
        assert!(!state.is_enabled(V1_SEND, true));
        assert!(state.is_enabled("later", true));
    }

    #[test]
    fn a_downgrade_only_apply_turns_flags_off_but_never_on() {
        let mut state = FeatureState::default();
        state.apply(
            flags(r#"{"features":{"v1_send":true,"a":true,"b":false}}"#),
            FeatureApply::Full,
            true,
        );
        state.apply(
            flags(r#"{"features":{"v1_send":true,"b":true,"c":true}}"#),
            FeatureApply::DowngradeOnly,
            true,
        );
        assert!(state.is_enabled(V1_SEND, true));
        assert!(
            !state.is_enabled("a", true),
            "a missing key turns a flag off"
        );
        assert!(
            !state.is_enabled("b", true),
            "a re-check never turns a flag on"
        );
        assert!(!state.is_enabled("c", true), "a re-check never adds a flag");

        state.apply(
            flags(r#"{"features":{"v1_send":false}}"#),
            FeatureApply::DowngradeOnly,
            true,
        );
        assert!(!state.is_enabled(V1_SEND, true));
        state.apply(
            flags(r#"{"features":{"v1_send":true}}"#),
            FeatureApply::DowngradeOnly,
            true,
        );
        assert!(
            !state.is_enabled(V1_SEND, true),
            "only a full apply turns it back on"
        );
    }

    #[test]
    fn an_ip_bucketed_result_reads_off_once_keys_load_until_refetched() {
        let mut state = FeatureState::default();
        state.apply(
            flags(r#"{"features":{"v1_send":true}}"#),
            FeatureApply::Full,
            false,
        );
        assert!(
            state.is_enabled(V1_SEND, false),
            "no keys: the IP answer applies"
        );
        assert!(!state.refetch_due(false));

        assert!(state.refetch_due(true));
        assert!(
            !state.is_enabled(V1_SEND, true),
            "keys loaded: off until refetched"
        );

        state.apply(
            flags(r#"{"features":{"v1_send":true}}"#),
            FeatureApply::Full,
            true,
        );
        assert!(!state.refetch_due(true));
        assert!(state.is_enabled(V1_SEND, true));
    }

    #[test]
    fn the_refetch_after_keys_load_may_turn_a_flag_on() {
        let mut state = FeatureState::default();
        state.apply(
            flags(r#"{"features":{"v1_send":false}}"#),
            FeatureApply::Full,
            false,
        );
        state.apply(
            flags(r#"{"features":{"v1_send":true}}"#),
            FeatureApply::Full,
            true,
        );
        assert!(state.is_enabled(V1_SEND, true));
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
