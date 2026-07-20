//! Fuzz `decrypt_event` end to end: base64 → bounded Thrift parse → signature
//! verification → decryption, with fixed keys loaded so the crypto paths run.
//! Any input must yield `Ok`/`Err`, never a panic.

#![no_main]

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chat_xdk_core::crypto::keys::XChatConversationKey;
use chat_xdk_core::{ChatCore, SigningKeyEntry};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::OnceLock;

struct Fixture {
    core: ChatCore,
    conversation_keys: HashMap<String, XChatConversationKey>,
    signing_keys: Vec<SigningKeyEntry>,
}

/// Same fixed key material as `tests/fixtures/sdk_vectors.json` (scalars 1/2,
/// conversation key ending in 3) so failures reproduce deterministically.
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut private_concat = [0u8; 64];
        private_concat[31] = 1;
        private_concat[63] = 2;
        let core = ChatCore::new();
        core.import_keys_with_version(&private_concat, "1")
            .expect("import keys");

        let mut ckey_bytes = vec![0u8; 32];
        ckey_bytes[31] = 3;
        let mut conversation_keys = HashMap::new();
        conversation_keys.insert(
            "1001".to_string(),
            XChatConversationKey::from_bytes(ckey_bytes).expect("valid key"),
        );

        let pubkeys = core.get_public_keys().expect("public keys");
        // Identity binding: the signing key signs the identity key's wire bytes.
        let identity_bytes = B64.decode(&pubkeys.identity).expect("identity b64");
        let binding = core.sign(&identity_bytes).expect("binding signature");
        let signing_keys = vec![SigningKeyEntry {
            user_id: "1111".to_string(),
            public_key_version: "1".to_string(),
            public_key: pubkeys.signing.clone(),
            identity_public_key: pubkeys.identity.clone(),
            identity_public_key_signature: B64.encode(binding),
        }];

        Fixture {
            core,
            conversation_keys,
            signing_keys,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();

    // Well-formed base64 over arbitrary bytes drives the parse + crypto path …
    let encoded = B64.encode(data);
    let _ = f
        .core
        .decrypt_event(&encoded, &f.conversation_keys, &f.signing_keys);

    // … and the raw input, when it is a string, drives the base64 error path.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = f
            .core
            .decrypt_event(s, &f.conversation_keys, &f.signing_keys);
    }
});
