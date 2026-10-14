//! Attachment keys remembered from decrypted messages.
//!
//! Media of a message that uses a message key is encrypted under a key
//! derived for each attachment, which a caller holding only the message's
//! conversation key cannot select. Decrypting the message records its
//! attachment keys here, filed under the conversation key that decrypted it,
//! so stream decryption given that conversation key can try them.

use std::collections::VecDeque;

use crate::crypto::hash::sha256;
use crate::crypto::keys::XChatConversationKey;

/// Most attachment keys held at once; the oldest are dropped first.
const CAPACITY: usize = 4096;

#[derive(Default)]
pub(crate) struct AttachmentKeyStore {
    entries: VecDeque<StoredKey>,
}

struct StoredKey {
    conversation_key_digest: [u8; 32],
    key_digest: [u8; 32],
    key: XChatConversationKey,
}

impl AttachmentKeyStore {
    /// File `key` under `conversation_key`, ignoring a key already filed.
    pub(crate) fn insert(
        &mut self,
        conversation_key: &XChatConversationKey,
        key: XChatConversationKey,
    ) {
        let conversation_key_digest = digest(conversation_key);
        let key_digest = digest(&key);
        if self.entries.iter().any(|e| {
            e.conversation_key_digest == conversation_key_digest && e.key_digest == key_digest
        }) {
            return;
        }
        if self.entries.len() == CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(StoredKey {
            conversation_key_digest,
            key_digest,
            key,
        });
    }

    /// The keys filed under `conversation_key`, newest first.
    pub(crate) fn keys_for(
        &self,
        conversation_key: &XChatConversationKey,
    ) -> Vec<XChatConversationKey> {
        let conversation_key_digest = digest(conversation_key);
        self.entries
            .iter()
            .rev()
            .filter(|e| e.conversation_key_digest == conversation_key_digest)
            .map(|e| e.key.clone())
            .collect()
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }
}

fn digest(key: &XChatConversationKey) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&sha256(key.encoded()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> XChatConversationKey {
        XChatConversationKey::from_bytes(vec![byte; 32]).unwrap()
    }

    #[test]
    fn keys_are_filed_per_conversation_key_newest_first() {
        let mut store = AttachmentKeyStore::default();
        store.insert(&key(1), key(10));
        store.insert(&key(2), key(20));
        store.insert(&key(1), key(11));

        let filed: Vec<Vec<u8>> = store
            .keys_for(&key(1))
            .iter()
            .map(|k| k.to_bytes())
            .collect();
        assert_eq!(filed, vec![vec![11u8; 32], vec![10u8; 32]]);
        assert_eq!(store.keys_for(&key(2)).len(), 1);
        assert!(store.keys_for(&key(3)).is_empty());
    }

    #[test]
    fn a_key_is_filed_once() {
        let mut store = AttachmentKeyStore::default();
        store.insert(&key(1), key(10));
        store.insert(&key(1), key(10));
        assert_eq!(store.keys_for(&key(1)).len(), 1);
    }

    #[test]
    fn the_oldest_key_is_dropped_at_capacity() {
        let mut store = AttachmentKeyStore::default();
        for i in 0..=CAPACITY {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
            store.insert(
                &key(1),
                XChatConversationKey::from_bytes(bytes.to_vec()).unwrap(),
            );
        }
        let filed = store.keys_for(&key(1));
        assert_eq!(filed.len(), CAPACITY);
        assert!(filed.iter().all(|k| k.encoded()[..8] != 0u64.to_le_bytes()));
    }

    #[test]
    fn clear_drops_every_key() {
        let mut store = AttachmentKeyStore::default();
        store.insert(&key(1), key(10));
        store.clear();
        assert!(store.keys_for(&key(1)).is_empty());
    }
}
