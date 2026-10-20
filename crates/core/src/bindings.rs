//! Feature switches for this repository's language bindings.
//!
//! Not part of the public API. Each binding fetches `GET /2/chat/features`
//! with its own HTTP stack when a chat is created, again with the key's bucket
//! once keys load, and re-checks it periodically, all without user
//! involvement. These are the calls it makes on the chat; sends then pick the
//! wire format from the applied flags.

pub use crate::features::{FeatureApply, FEATURES_ENDPOINT, V1_SEND};

use crate::error::SdkError;

/// The feature-switch state of a chat, as the bindings drive it.
pub trait FeatureSwitches {
    /// The bucket `GET /2/chat/features` evaluates this chat's flags for,
    /// derived from the loaded identity public key; `None` until keys load.
    fn feature_bucket(&self) -> Option<u16>;

    /// Apply a `GET /2/chat/features` response body. `bucket` is the bucket
    /// the request carried, or `None` when it carried none. A body that is not
    /// a JSON object with a `features` object is an error and changes nothing.
    fn apply_feature_config(
        &self,
        json: &str,
        mode: FeatureApply,
        bucket: Option<u16>,
    ) -> Result<(), SdkError>;

    /// Whether the feature switch `name` is on.
    fn is_enabled(&self, name: &str) -> bool;

    /// Whether keys are loaded but no response to a request carrying their
    /// bucket has applied, so the flags must be fetched with the key's bucket.
    fn feature_refetch_due(&self) -> bool;
}

impl FeatureSwitches for crate::ChatCore {
    fn feature_bucket(&self) -> Option<u16> {
        crate::ChatCore::feature_bucket(self)
    }

    fn apply_feature_config(
        &self,
        json: &str,
        mode: FeatureApply,
        bucket: Option<u16>,
    ) -> Result<(), SdkError> {
        crate::ChatCore::apply_feature_config(self, json, mode, bucket)
    }

    fn is_enabled(&self, name: &str) -> bool {
        crate::ChatCore::is_enabled(self, name)
    }

    fn feature_refetch_due(&self) -> bool {
        crate::ChatCore::feature_refetch_due(self)
    }
}

#[cfg(feature = "juicebox")]
impl FeatureSwitches for crate::Chat {
    fn feature_bucket(&self) -> Option<u16> {
        crate::Chat::feature_bucket(self)
    }

    fn apply_feature_config(
        &self,
        json: &str,
        mode: FeatureApply,
        bucket: Option<u16>,
    ) -> Result<(), SdkError> {
        crate::Chat::apply_feature_config(self, json, mode, bucket)
    }

    fn is_enabled(&self, name: &str) -> bool {
        crate::Chat::is_enabled(self, name)
    }

    fn feature_refetch_due(&self) -> bool {
        crate::Chat::feature_refetch_due(self)
    }
}
