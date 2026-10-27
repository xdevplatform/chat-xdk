//! Key management: generating, exporting and importing keys, the public
//! keys and fingerprint, key bindings, and sign and verify.

use super::*;

/// `generate_keypairs` produces a bidirectional cross-signature.
///
/// - `identity_public_key_signature`: signing key signs identity SPKI
/// - `signing_public_key_signature`:  identity key signs signing SPKI
///
/// Both signatures must verify against the corresponding public key.
#[test]
fn generate_keypairs_produces_bidirectional_cross_signatures() {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;
    use p256::PublicKey;

    let core = ChatCore::new();
    let payload = core.generate_keypairs().unwrap();
    let reg = &payload.public_key;

    // Decode public keys
    let identity_spki_bytes =
        crate::protocol::serialization::base64_decode(&reg.public_key).unwrap();
    let signing_spki_bytes =
        crate::protocol::serialization::base64_decode(&reg.signing_public_key).unwrap();

    let identity_pk =
        PublicKey::from_public_key_der(&identity_spki_bytes).expect("identity SPKI should parse");
    let signing_pk =
        PublicKey::from_public_key_der(&signing_spki_bytes).expect("signing SPKI should parse");

    let identity_vk = VerifyingKey::from(identity_pk);
    let signing_vk = VerifyingKey::from(signing_pk);

    // 1. Verify identity_public_key_signature: signing key signed identity SPKI
    let id_sig_bytes =
        crate::protocol::serialization::base64_decode(&reg.identity_public_key_signature).unwrap();
    let id_sig = Signature::from_slice(&id_sig_bytes)
        .expect("identity_public_key_signature should be valid raw r||s");
    signing_vk
        .verify(&identity_spki_bytes, &id_sig)
        .expect("signing key should verify identity SPKI signature");

    // 2. Verify signing_public_key_signature: identity key signed signing SPKI
    let spk_sig_b64 = reg
        .signing_public_key_signature
        .as_ref()
        .expect("signing_public_key_signature should be Some");
    let spk_sig_bytes = crate::protocol::serialization::base64_decode(spk_sig_b64).unwrap();
    let spk_sig = Signature::from_slice(&spk_sig_bytes)
        .expect("signing_public_key_signature should be valid raw r||s");
    identity_vk
        .verify(&signing_spki_bytes, &spk_sig)
        .expect("identity key should verify signing SPKI signature");
}

// export_keys / import_keys tests

#[test]
fn export_import_keys_roundtrip() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    // Export keys
    let exported = core.export_keys().unwrap();
    assert!(!exported.is_empty());

    // Get public keys before lock
    let public_keys_before = core.get_public_keys().unwrap();

    // Lock (clear keys)
    core.lock();
    assert!(!core.has_identity_key());
    assert!(!core.is_unlocked());

    // Import keys
    core.import_keys(&ImportKeysParams::new(exported.to_vec()))
        .unwrap();
    assert!(core.has_identity_key());
    assert!(core.is_unlocked());

    // Verify keys match
    let public_keys_after = core.get_public_keys().unwrap();
    assert_eq!(public_keys_before.identity, public_keys_after.identity);
    assert_eq!(public_keys_before.signing, public_keys_after.signing);
}

#[test]
fn import_keys_invalid_format_errors() {
    let core = ChatCore::new();

    // Wrong size: not 32 or 64 bytes
    let result = core.import_keys(&ImportKeysParams::new([0u8; 16].to_vec()));
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("Invalid key format"));
}

#[test]
fn caller_input_errors_are_invalid_input() {
    use crate::error::ErrorKind;
    let core = ChatCore::new();
    let reg = core.generate_keypairs().unwrap();
    core.set_identity(&SetIdentityParams::new("111", "1"))
        .unwrap();
    let signature = core.sign(b"data").unwrap();
    let signing_key = &reg.public_key.signing_public_key;

    let kinds = [
        core.import_keys(&ImportKeysParams::new(vec![0u8; 16]))
            .unwrap_err()
            .kind(),
        core.encrypt_message(
            &crate::EncryptMessageParams::new("111:222", "hi")
                .with_conversation_key(vec![0u8; 3], "1"),
        )
        .unwrap_err()
        .kind(),
        core.prepare_conversation_key_change(&ConversationKeyChangeParams::new(vec![]))
            .unwrap_err()
            .kind(),
        core.verify("not base64!", &signature, b"data")
            .unwrap_err()
            .kind(),
        core.verify(signing_key, &signature[..10], b"data")
            .unwrap_err()
            .kind(),
        core.verify_key_binding("not base64!", signing_key, "AAAA")
            .unwrap_err()
            .kind(),
        core.matches_registered_key("not base64!")
            .unwrap_err()
            .kind(),
        core.prepare_message_delete(&MessageDeleteParams::new("1,2", vec!["5".into()], true))
            .unwrap_err()
            .kind(),
    ];
    for kind in kinds {
        assert_eq!(kind, ErrorKind::InvalidInput);
    }
    assert!(core.verify(signing_key, &signature, b"data").unwrap());

    core.lock();
    let locked = core
        .encrypt_message(
            &crate::EncryptMessageParams::new("111:222", "hi")
                .with_conversation_key(vec![0u8; 32], "1"),
        )
        .unwrap_err();
    assert_eq!(locked.kind(), ErrorKind::InvalidState);
}

#[test]
fn export_keys_without_keys_errors() {
    let core = ChatCore::new();

    let result = core.export_keys();
    assert!(result.is_err());
}

// Key management state tests

#[test]
fn is_unlocked_and_has_identity_key() {
    let core = ChatCore::new();

    // No keys loaded
    assert!(!core.is_unlocked());
    assert!(!core.has_identity_key());

    // Generate keys
    core.generate_keypairs().unwrap();
    assert!(core.is_unlocked());
    assert!(core.has_identity_key());

    // Lock
    core.lock();
    assert!(!core.is_unlocked());
    assert!(!core.has_identity_key());
}

#[test]
fn get_public_keys_without_keys_errors() {
    let core = ChatCore::new();
    assert!(core.get_public_keys().is_err());
}

#[test]
fn get_public_key_fingerprint_works() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let fingerprint = core.get_public_key_fingerprint().unwrap();
    assert!(!fingerprint.is_empty());
    // URL-safe base64 of SHA-256 (32 bytes → 43 chars without padding)
    assert_eq!(fingerprint.len(), 43);
}

#[test]
fn get_public_key_fingerprint_without_keys_errors() {
    let core = ChatCore::new();
    assert!(core.get_public_key_fingerprint().is_err());
}

#[test]
fn verify_key_binding_roundtrip() {
    // identity_public_key_signature = signing key signing the
    // SPKI-encoded identity key (raw r||s). The registration payload
    // carries the SPKI-encoded keys — the same format the X API
    // returns on the public keys endpoint.
    let core = ChatCore::new();
    let payload = core.generate_keypairs().unwrap();

    let identity_spki = payload.public_key.public_key.clone();
    let signing_spki = payload.public_key.signing_public_key.clone();
    let sig = payload.public_key.identity_public_key_signature.clone();

    // Valid binding verifies.
    let ok = core
        .verify_key_binding(&identity_spki, &signing_spki, &sig)
        .unwrap();
    assert!(ok, "valid key binding should verify");

    // Wrong identity key fails.
    let other = ChatCore::new();
    let other_payload = other.generate_keypairs().unwrap();
    let bad = core
        .verify_key_binding(&other_payload.public_key.public_key, &signing_spki, &sig)
        .unwrap();
    assert!(!bad, "binding with wrong identity key must fail");
}

#[test]
fn matches_registered_key_accepts_both_encodings() {
    let core = ChatCore::new();
    let payload = core.generate_keypairs().unwrap();

    // SPKI/DER form — what the X API returns for a registered key.
    let spki = payload.public_key.public_key;
    assert!(core.matches_registered_key(&spki).unwrap());

    // Raw SEC1 point — what get_public_keys returns.
    let raw = core.get_public_keys().unwrap().identity;
    assert!(core.matches_registered_key(&raw).unwrap());
}

#[test]
fn matches_registered_key_rejects_other_key() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let other = ChatCore::new();
    let other_payload = other.generate_keypairs().unwrap();
    assert!(!core
        .matches_registered_key(&other_payload.public_key.public_key)
        .unwrap());
}

#[test]
fn matches_registered_key_without_keys_errors() {
    let core = ChatCore::new();
    assert!(core.matches_registered_key("AAAA").is_err());
}

#[test]
fn matches_registered_key_invalid_base64_errors() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    assert!(core.matches_registered_key("not base64!!").is_err());
}

#[test]
fn matches_registered_key_garbage_bytes_is_false() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();
    // Valid base64 of bytes that are not a public key in either encoding.
    let garbage = base64_encode(&[0u8; 65]);
    assert!(!core.matches_registered_key(&garbage).unwrap());
}

#[test]
fn generate_keypairs_returns_registration_payload() {
    let core = ChatCore::new();
    let payload = core.generate_keypairs().unwrap();

    assert!(!payload.public_key.public_key.is_empty());
    assert!(!payload.public_key.signing_public_key.is_empty());
    assert!(!payload.public_key.identity_public_key_signature.is_empty());
    assert_eq!(payload.public_key.registration_method, "CustomPin");
    assert!(payload.public_key.public_key_fingerprint.is_some());
    assert!(payload.public_key.signing_public_key_signature.is_some());
}

// sign / verify tests

#[test]
fn sign_and_verify_roundtrip() {
    let core = ChatCore::new();
    core.generate_keypairs().unwrap();

    let data = b"Hello, world!";
    let signature = core.sign(data).unwrap();
    assert!(!signature.is_empty());

    let public_keys = core.get_public_keys().unwrap();
    let verified = core.verify(&public_keys.signing, &signature, data).unwrap();
    assert!(verified);

    // Wrong data should not verify
    let bad_verified = core
        .verify(&public_keys.signing, &signature, b"wrong data")
        .unwrap();
    assert!(!bad_verified);
}

#[test]
fn sign_without_keys_errors() {
    let core = ChatCore::new();
    assert!(core.sign(b"data").is_err());
}

// ChatCore::default() test

#[test]
fn chatcore_default_is_new() {
    let core = ChatCore::default();
    assert!(!core.is_unlocked());
    assert!(!core.has_identity_key());
}

// verify_key_binding negative cases

/// A tampered `identity_public_key_signature` must not verify.
#[test]
fn verify_key_binding_tampered_signature_fails() {
    let core = ChatCore::new();
    let payload = core.generate_keypairs().unwrap();

    let identity_spki = payload.public_key.public_key.clone();
    let signing_spki = payload.public_key.signing_public_key.clone();

    // Flip a byte in the raw signature bytes and re-encode.
    let mut sig_bytes = base64_decode(&payload.public_key.identity_public_key_signature).unwrap();
    sig_bytes[0] ^= 0xFF;
    let tampered_sig = base64_encode(&sig_bytes);

    let ok = core
        .verify_key_binding(&identity_spki, &signing_spki, &tampered_sig)
        .unwrap();
    assert!(!ok, "tampered signature must not verify");
}

/// A valid signature verified against the wrong *signing* key must fail.
#[test]
fn verify_key_binding_mismatched_signing_key_fails() {
    let core = ChatCore::new();
    let payload = core.generate_keypairs().unwrap();

    let identity_spki = payload.public_key.public_key.clone();
    let sig = payload.public_key.identity_public_key_signature.clone();

    // A different keypair's signing key did not produce this signature.
    let other = ChatCore::new();
    let other_payload = other.generate_keypairs().unwrap();
    let wrong_signing_spki = other_payload.public_key.signing_public_key.clone();

    let bad = core
        .verify_key_binding(&identity_spki, &wrong_signing_spki, &sig)
        .unwrap();
    assert!(!bad, "binding with wrong signing key must fail");
}

/// Sanity: the binding produced by `generate_keypairs` verifies.
#[test]
fn verify_key_binding_valid_passes() {
    let core = ChatCore::new();
    let payload = core.generate_keypairs().unwrap();

    let ok = core
        .verify_key_binding(
            &payload.public_key.public_key,
            &payload.public_key.signing_public_key,
            &payload.public_key.identity_public_key_signature,
        )
        .unwrap();
    assert!(ok, "valid binding from generate_keypairs should verify");
}
