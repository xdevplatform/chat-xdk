//! In-memory keypair management.
//!
//! Manages the lifecycle of unlocked keys in memory, coordinating
//! between Juicebox (persistent storage) and crypto operations.
//!
//! Keys are stored behind `Arc` to avoid cloning private key bytes
//! on every access. The `RwLock` uses poison recovery so that a panic
//! in an unrelated thread does not permanently lock out key access.

use crate::crypto::key_factory::KeyFactory;
use crate::crypto::keys::{KeypairPurpose, XChatKeyPair, XChatPrivateKeys};
use crate::error::{CryptoError, KeyError};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// All key state, held under a **single** lock.
///
/// Identity, signing key, and key version are read and written together
/// so observers can never see a torn state (e.g. identity loaded but
/// signing key missing mid-`clear()`).
#[derive(Default)]
struct KeyState {
    /// Identity keypair (ECIES decryption of conversation keys).
    identity: Option<Arc<XChatKeyPair>>,
    /// Signing keypair (ECDSA event signatures).
    signing: Option<Arc<XChatKeyPair>>,
    /// Public key version the identity key was registered under; used to
    /// filter participant keys during conversation key extraction.
    key_version: Option<String>,
}

/// Manages identity and signing keypairs in memory.
///
/// Keys are loaded from Juicebox on unlock and held in memory
/// for the duration of the session. Stored behind `Arc` so callers
/// get a cheap reference-counted handle instead of cloning key bytes.
pub struct KeypairManager {
    state: RwLock<KeyState>,
}

// Private lock helpers — recover from poisoning instead of panicking.
//
// A poisoned lock means another thread panicked while holding it. The key
// data inside is still valid (it's just bytes), so we recover by ignoring
// the poison flag. This prevents a panic in an unrelated code path from
// permanently bricking the SDK.

impl KeypairManager {
    fn read_state(&self) -> RwLockReadGuard<'_, KeyState> {
        self.state.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write_state(&self) -> RwLockWriteGuard<'_, KeyState> {
        self.state.write().unwrap_or_else(|e| e.into_inner())
    }
}

// Public API

impl KeypairManager {
    /// Create a new keypair manager with no keys loaded.
    pub fn new() -> Self {
        Self {
            state: RwLock::new(KeyState::default()),
        }
    }

    /// Check if the identity key is currently loaded in memory.
    pub fn has_keypair(&self) -> bool {
        self.read_state().identity.is_some()
    }

    /// Check if the signing key is currently loaded in memory.
    pub fn has_signing_keypair(&self) -> bool {
        self.read_state().signing.is_some()
    }

    /// Check that both identity and signing keys are loaded, as a single
    /// consistent snapshot.
    ///
    /// Both fields are read under one lock acquisition, so this can never
    /// observe a torn state from a concurrent `clear()`/load.
    pub fn has_both_keypairs(&self) -> bool {
        let state = self.read_state();
        state.identity.is_some() && state.signing.is_some()
    }

    /// Get a reference-counted handle to the identity keypair.
    ///
    /// Returns `Arc<XChatKeyPair>` — no private key bytes are copied.
    pub fn get_identity_keypair(&self) -> Result<Arc<XChatKeyPair>, KeyError> {
        self.read_state()
            .identity
            .as_ref()
            .cloned() // clones the Arc (cheap ref-count bump), not the key bytes
            .ok_or(KeyError::NotUnlocked)
    }

    /// Get a reference-counted handle to the signing keypair.
    ///
    /// Returns `Arc<XChatKeyPair>` — no private key bytes are copied.
    pub fn get_signing_keypair(&self) -> Result<Arc<XChatKeyPair>, KeyError> {
        self.read_state()
            .signing
            .as_ref()
            .cloned()
            .ok_or(KeyError::NotUnlocked)
    }

    /// Load keypairs by reconstructing them from private key bytes.
    pub fn load_from_private_keys(
        &self,
        private_keys: &XChatPrivateKeys,
    ) -> Result<(), CryptoError> {
        let identity = KeyFactory::get_keypair_from_private_key_bytes(
            private_keys.identity.encoded(),
            KeypairPurpose::Identity,
        )?;

        let signing = if let Some(ref signing_key) = private_keys.signing {
            Some(KeyFactory::get_keypair_from_private_key_bytes(
                signing_key.encoded(),
                KeypairPurpose::Signing,
            )?)
        } else {
            None
        };

        let mut state = self.write_state();
        state.identity = Some(Arc::new(identity));
        state.signing = signing.map(Arc::new);
        // The stored version belongs to the previous identity, so reset it;
        // the caller sets the new one after import.
        state.key_version = None;

        Ok(())
    }

    /// Store keypairs directly (used after key generation).
    pub fn set_keypairs(&self, identity: XChatKeyPair, signing: Option<XChatKeyPair>) {
        let mut state = self.write_state();
        state.identity = Some(Arc::new(identity));
        state.signing = signing.map(Arc::new);
        state.key_version = None;
    }

    /// Set the public key version for the loaded identity key.
    pub fn set_key_version(&self, version: String) {
        self.write_state().key_version = Some(version);
    }

    /// Get the public key version, if set.
    pub fn get_key_version(&self) -> Option<String> {
        self.read_state().key_version.clone()
    }

    /// Clear all keys from memory, atomically.
    ///
    /// All fields are cleared under one lock acquisition so concurrent
    /// readers see either the fully-loaded or fully-cleared state.
    /// The underlying key bytes are zeroized once the last `Arc` handle
    /// is dropped (via `ZeroizeOnDrop` on `XChatKeyPair`).
    pub fn clear(&self) {
        let mut state = self.write_state();
        state.identity = None;
        state.signing = None;
        state.key_version = None;
    }

    /// Export private keys for Juicebox storage.
    ///
    /// This is the one place where private key bytes are necessarily copied
    /// out of the `Arc`, since the caller needs an owned `XChatPrivateKeys`.
    /// Both keys are read under a single lock acquisition so the export is
    /// a consistent snapshot.
    pub fn get_private_keys(&self) -> Result<XChatPrivateKeys, KeyError> {
        let state = self.read_state();
        let identity = state
            .identity
            .as_ref()
            .ok_or(KeyError::NotUnlocked)?
            .private
            .clone();

        let signing = state.signing.as_ref().map(|kp| kp.private.clone());

        Ok(XChatPrivateKeys::new(identity, signing))
    }
}

impl Default for KeypairManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for KeypairManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeypairManager")
            .field("has_identity", &self.has_keypair())
            .field("has_signing", &self.has_signing_keypair())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_manager_is_empty() {
        let manager = KeypairManager::new();
        assert!(!manager.has_keypair());
        assert!(!manager.has_signing_keypair());
    }

    #[test]
    fn test_get_keypair_when_not_unlocked() {
        let manager = KeypairManager::new();
        assert!(matches!(
            manager.get_identity_keypair(),
            Err(KeyError::NotUnlocked)
        ));
        assert!(matches!(
            manager.get_signing_keypair(),
            Err(KeyError::NotUnlocked)
        ));
    }

    #[test]
    fn test_set_and_get_keypairs() {
        let manager = KeypairManager::new();

        let identity = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let signing = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();

        manager.set_keypairs(identity.clone(), Some(signing.clone()));

        assert!(manager.has_keypair());
        assert!(manager.has_signing_keypair());

        let retrieved_identity = manager.get_identity_keypair().unwrap();
        assert_eq!(
            retrieved_identity.public.encoded(),
            identity.public.encoded()
        );

        let retrieved_signing = manager.get_signing_keypair().unwrap();
        assert_eq!(retrieved_signing.public.encoded(), signing.public.encoded());
    }

    #[test]
    fn test_clear_keypairs() {
        let manager = KeypairManager::new();

        let identity = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        manager.set_keypairs(identity, None);

        assert!(manager.has_keypair());

        manager.clear();

        assert!(!manager.has_keypair());
        assert!(matches!(
            manager.get_identity_keypair(),
            Err(KeyError::NotUnlocked)
        ));
    }

    #[test]
    fn test_load_from_private_keys() {
        let manager = KeypairManager::new();

        // Generate keypairs
        let identity = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let signing = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();

        // Create private keys container
        let private_keys =
            XChatPrivateKeys::new(identity.private.clone(), Some(signing.private.clone()));

        // Load from private keys
        manager.load_from_private_keys(&private_keys).unwrap();

        assert!(manager.has_keypair());
        assert!(manager.has_signing_keypair());

        // Verify the public keys match (derived from private keys)
        let loaded_identity = manager.get_identity_keypair().unwrap();
        assert_eq!(loaded_identity.public.encoded(), identity.public.encoded());

        let loaded_signing = manager.get_signing_keypair().unwrap();
        assert_eq!(loaded_signing.public.encoded(), signing.public.encoded());
    }

    #[test]
    fn test_debug_impl() {
        let manager = KeypairManager::new();
        let debug = format!("{:?}", manager);
        assert!(debug.contains("has_identity"));
        assert!(debug.contains("false"));
    }

    #[test]
    fn test_identity_without_signing() {
        let manager = KeypairManager::new();
        let identity = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        manager.set_keypairs(identity, None);

        assert!(manager.has_keypair());
        assert!(!manager.has_signing_keypair());
        assert!(manager.get_identity_keypair().is_ok());
        assert!(manager.get_signing_keypair().is_err());
    }

    #[test]
    fn test_get_private_keys() {
        let manager = KeypairManager::new();

        let identity = KeyFactory::generate_keypair(KeypairPurpose::Identity).unwrap();
        let signing = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();

        manager.set_keypairs(identity.clone(), Some(signing.clone()));

        let private_keys = manager.get_private_keys().unwrap();
        assert_eq!(private_keys.identity.encoded(), identity.private.encoded());
        assert_eq!(
            private_keys.signing.as_ref().unwrap().encoded(),
            signing.private.encoded()
        );
    }
}
