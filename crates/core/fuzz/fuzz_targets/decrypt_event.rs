//! Fuzz `decrypt_event` end to end: base64 → bounded Thrift parse → signature
//! verification → decryption, with fixed keys loaded so the crypto paths run.
//! Any input must yield `Ok`/`Err`, never a panic.

#![no_main]

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chat_xdk_core::crypto::keys::XChatConversationKey;
use chat_xdk_core::{ChatCore, DecryptEventParams, ImportKeysParams, SigningKeyEntry};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::OnceLock;

struct Fixture {
    core: ChatCore,
    conversation_keys: HashMap<String, XChatConversationKey>,
    signing_keys: Vec<SigningKeyEntry>,
}

impl Fixture {
    fn params(&self, event_b64: impl Into<String>) -> DecryptEventParams {
        DecryptEventParams::new(event_b64, self.conversation_keys.clone())
            .with_signing_keys(self.signing_keys.clone())
    }
}

/// The keys, conversation key and signing-key entry of
/// `tests/fixtures/sdk_vectors.json`, so failures reproduce deterministically
/// and the fixture's events decrypt and verify.
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../../tests/fixtures/sdk_vectors.json"))
                .expect("sdk_vectors.json");
        let field = |name: &str| {
            vectors[name]
                .as_str()
                .unwrap_or_else(|| panic!("sdk_vectors.json has no {name}"))
        };
        let bytes = |name: &str| {
            B64.decode(field(name))
                .unwrap_or_else(|_| panic!("sdk_vectors.json {name} is not base64"))
        };

        let core = ChatCore::new();
        core.import_keys(
            &ImportKeysParams::new(bytes("private_keys_concat_b64"))
                .with_signing_key_version(field("event_recipient_key_version")),
        )
        .expect("import keys");

        let mut conversation_keys = HashMap::new();
        conversation_keys.insert(
            field("event_conversation_key_version").to_string(),
            XChatConversationKey::from_bytes(bytes("conversation_key_b64")).expect("valid key"),
        );

        // `ChatCore::sign` refuses to sign a public key, so the signing key's
        // binding over the identity key is the fixture's.
        let signing_keys = vec![SigningKeyEntry::new(
            field("event_sender_id"),
            field("event_signing_key_version"),
            field("signing_public_b64"),
            field("identity_public_b64"),
            field("identity_public_key_signature_b64"),
        )];

        let fixture = Fixture {
            core,
            conversation_keys,
            signing_keys,
        };
        // Keys that no longer open the fixture's own message would leave every
        // input on the error paths: fail here instead.
        fixture
            .core
            .decrypt_event(&fixture.params(field("event_message_b64")))
            .expect("the fixture message decrypts and verifies");
        fixture
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();

    // Well-formed base64 over arbitrary bytes drives the parse + crypto path …
    let _ = f.core.decrypt_event(&f.params(B64.encode(data)));

    // … and the raw input, when it is a string, drives the base64 error path.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = f.core.decrypt_event(&f.params(s));
    }
});
