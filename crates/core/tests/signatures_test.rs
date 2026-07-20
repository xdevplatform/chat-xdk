//! Integration tests for the signatures module.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chat_xdk_core::crypto::key_factory::KeyFactory;
use chat_xdk_core::crypto::keys::KeypairPurpose;
use chat_xdk_core::signatures::{build_ckey_change_signature, build_group_member_add_signature};

fn decode_no_pad(s: &str) -> Vec<u8> {
    STANDARD_NO_PAD.decode(s).unwrap()
}

#[test]
fn test_group_member_add_signature_roundtrip() {
    let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();

    let sig = build_group_member_add_signature(
        &kp.private,
        "1",
        "msg-uuid-1",
        "sender-100",
        "conv-200",
        &["new-user-1".to_string(), "new-user-2".to_string()],
        &["existing-1".to_string(), "existing-2".to_string()],
        &["existing-1".to_string()],
        Some("Test Group"),
        None,
        Some(86400000),
        None,
        "42",
    )
    .unwrap();

    // Verify the payload format
    assert!(sig
        .signature_payload
        .starts_with("GroupChangeEvent.GroupMemberAddChange,"));
    assert!(sig.signature_payload.contains("msg-uuid-1"));
    assert!(sig.signature_payload.contains("sender-100"));
    assert!(sig.signature_payload.contains("conv-200"));
    assert!(sig.signature_payload.contains("new-user-1"));
    assert!(sig.signature_payload.contains("new-user-2"));
    assert!(sig.signature_payload.contains("Test Group"));
    assert!(sig.signature_payload.contains("86400000"));
    // ckey version followed by the null screen-capture slot
    assert!(sig.signature_payload.ends_with(",42,null"));
    assert_eq!(sig.signature_version, "7");
    assert_eq!(sig.public_key_version, "1");

    // Verify the signature is cryptographically valid
    let sig_bytes = decode_no_pad(&sig.signature);
    let valid =
        KeyFactory::verify(&kp.public, &sig_bytes, sig.signature_payload.as_bytes()).unwrap();
    assert!(valid, "GroupMemberAdd signature should be verifiable");
}

#[test]
fn test_ckey_change_signature_roundtrip() {
    let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
    let ckey: Vec<u8> = (0u8..32).collect();

    let sig = build_ckey_change_signature(
        &kp.private,
        "1",
        "msg-uuid-2",
        "sender-100",
        "conv-200",
        "99",
        &ckey,
    )
    .unwrap();

    // The payload embeds the plaintext conversation key and is withheld
    assert!(sig.signature_payload.is_empty());
    assert_eq!(sig.signature_version, "7");

    // v7 signs the plaintext ckey bytes (base64 no-padding); reconstruct the
    // signed bytes to pin the wire format and verify the signature
    let expected_payload = format!(
        "ConversationKeyChangeEvent,msg-uuid-2,sender-100,conv-200,99,{}",
        STANDARD_NO_PAD.encode(&ckey)
    );
    let sig_bytes = decode_no_pad(&sig.signature);
    let valid = KeyFactory::verify(&kp.public, &sig_bytes, expected_payload.as_bytes()).unwrap();
    assert!(valid);
}

#[test]
fn test_group_member_add_empty_optional_fields() {
    let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();

    let sig = build_group_member_add_signature(
        &kp.private,
        "1",
        "msg-1",
        "sender-1",
        "conv-1",
        &["new-1".to_string()],
        &["existing-1".to_string()],
        &["existing-1".to_string()],
        None, // no title
        None, // no avatar
        None, // no ttl
        None, // no screen-capture blocking
        "1",
    )
    .unwrap();

    // Absent optional fields render as the "null" sentinel (title, avatar, ttl)
    assert!(sig.signature_payload.contains("null,null,null"));
    assert!(!sig.signature.is_empty());

    // Signature should still verify
    let sig_bytes = decode_no_pad(&sig.signature);
    let valid =
        KeyFactory::verify(&kp.public, &sig_bytes, sig.signature_payload.as_bytes()).unwrap();
    assert!(valid);
}

#[test]
fn test_group_member_add_signs_optional_fields() {
    let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();

    let sig = build_group_member_add_signature(
        &kp.private,
        "2",
        "msg-3",
        "admin-1",
        "conv-300",
        &["new-1".to_string()],
        &["admin-1".to_string(), "member-2".to_string()],
        &["admin-1".to_string()],
        Some("My Group"),
        Some("https://example.com/avatar.png"),
        None,
        None,
        "5",
    )
    .unwrap();

    assert!(sig.signature_payload.contains("My Group"));
    assert!(sig
        .signature_payload
        .contains("https://example.com/avatar.png"));
    assert_eq!(sig.public_key_version, "2");

    let sig_bytes = decode_no_pad(&sig.signature);
    let valid =
        KeyFactory::verify(&kp.public, &sig_bytes, sig.signature_payload.as_bytes()).unwrap();
    assert!(valid);
}

#[test]
fn test_ckey_change_single_participant() {
    let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();

    let ckey = vec![42u8; 32];
    let sig = build_ckey_change_signature(
        &kp.private,
        "1",
        "msg-single",
        "sender-1",
        "conv-1",
        "10",
        &ckey,
    )
    .unwrap();

    // The payload embeds the plaintext conversation key and is withheld
    assert!(sig.signature_payload.is_empty());

    let expected_payload = format!(
        "ConversationKeyChangeEvent,msg-single,sender-1,conv-1,10,{}",
        STANDARD_NO_PAD.encode(&ckey)
    );
    let sig_bytes = decode_no_pad(&sig.signature);
    let valid = KeyFactory::verify(&kp.public, &sig_bytes, expected_payload.as_bytes()).unwrap();
    assert!(valid);
}

#[test]
fn test_signature_fails_with_wrong_key() {
    let kp1 = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
    let kp2 = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();

    let sig = build_group_member_add_signature(
        &kp1.private,
        "1",
        "msg-1",
        "sender-1",
        "conv-1",
        &["new-1".to_string()],
        &[],
        &[],
        None,
        None,
        None,
        None,
        "1",
    )
    .unwrap();

    // Verify with wrong key should fail
    let sig_bytes = decode_no_pad(&sig.signature);
    let valid =
        KeyFactory::verify(&kp2.public, &sig_bytes, sig.signature_payload.as_bytes()).unwrap();
    assert!(!valid, "Signature should not verify with wrong key");
}

#[test]
fn test_group_member_add_all_optional_fields_roundtrip() {
    let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();

    let sig = build_group_member_add_signature(
        &kp.private,
        "3",
        "msg-allopt",
        "admin-42",
        "conv-999",
        &[
            "new-a".to_string(),
            "new-b".to_string(),
            "new-c".to_string(),
        ],
        &["mem-1".to_string(), "mem-2".to_string()],
        &["admin-42".to_string()],
        Some("Engineering Team"),
        Some("https://cdn.example.com/avatar.png"),
        Some(7_200_000), // 2 hours
        None,
        "77",
    )
    .unwrap();

    // Verify all optional fields present in payload
    assert!(sig.signature_payload.contains("Engineering Team"));
    assert!(sig
        .signature_payload
        .contains("https://cdn.example.com/avatar.png"));
    assert!(sig.signature_payload.contains("7200000"));
    // ckey version followed by the null screen-capture slot
    assert!(sig.signature_payload.ends_with(",77,null"));
    assert_eq!(sig.public_key_version, "3");
    assert_eq!(sig.signature_version, "7");

    // Cryptographic roundtrip
    let sig_bytes = decode_no_pad(&sig.signature);
    let valid =
        KeyFactory::verify(&kp.public, &sig_bytes, sig.signature_payload.as_bytes()).unwrap();
    assert!(valid, "Signature with all optional fields should verify");
}

#[test]
fn test_ckey_change_three_participants_roundtrip() {
    let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();

    let ckey: Vec<u8> = (0u8..32).collect();
    let sig = build_ckey_change_signature(
        &kp.private,
        "5",
        "msg-ckey-3p",
        "sender-root",
        "conv-group",
        "200",
        &ckey,
    )
    .unwrap();

    // The payload embeds the plaintext conversation key and is withheld
    assert!(sig.signature_payload.is_empty());
    assert_eq!(sig.public_key_version, "5");

    let expected_payload = format!(
        "ConversationKeyChangeEvent,msg-ckey-3p,sender-root,conv-group,200,{}",
        STANDARD_NO_PAD.encode(&ckey)
    );
    let sig_bytes = decode_no_pad(&sig.signature);
    let valid = KeyFactory::verify(&kp.public, &sig_bytes, expected_payload.as_bytes()).unwrap();
    assert!(valid);
}

#[test]
fn test_group_member_add_many_members() {
    let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();

    let new_members: Vec<String> = (0..10).map(|i| format!("new-{}", i)).collect();
    let current_members: Vec<String> = (0..20).map(|i| format!("mem-{}", i)).collect();
    let admins: Vec<String> = (0..3).map(|i| format!("admin-{}", i)).collect();

    let sig = build_group_member_add_signature(
        &kp.private,
        "1",
        "msg-large",
        "admin-0",
        "conv-large",
        &new_members,
        &current_members,
        &admins,
        Some("Large Group"),
        Some("https://example.com/large-avatar.png"),
        Some(86_400_000),
        None,
        "100",
    )
    .unwrap();

    // Verify all members are in the payload
    for m in &new_members {
        assert!(sig.signature_payload.contains(m.as_str()));
    }
    for m in &current_members {
        assert!(sig.signature_payload.contains(m.as_str()));
    }

    // Verify signature
    let sig_bytes = decode_no_pad(&sig.signature);
    let valid =
        KeyFactory::verify(&kp.public, &sig_bytes, sig.signature_payload.as_bytes()).unwrap();
    assert!(valid, "Large group add should produce valid signature");
}

#[test]
fn test_ckey_change_signature_fails_verification_with_tampered_payload() {
    let kp = KeyFactory::generate_keypair(KeypairPurpose::Signing).unwrap();
    let ckey = vec![99u8; 32];

    let sig = build_ckey_change_signature(
        &kp.private,
        "1",
        "msg-tamper",
        "sender-1",
        "conv-1",
        "1",
        &ckey,
    )
    .unwrap();

    // The payload is withheld from the signature; reconstruct the signed
    // bytes, then tamper with them
    let expected_payload = format!(
        "ConversationKeyChangeEvent,msg-tamper,sender-1,conv-1,1,{}",
        STANDARD_NO_PAD.encode(&ckey)
    );
    let sig_bytes = decode_no_pad(&sig.signature);
    let valid = KeyFactory::verify(&kp.public, &sig_bytes, expected_payload.as_bytes()).unwrap();
    assert!(valid, "Reconstructed payload should verify");

    let tampered = expected_payload.replace("sender-1", "attacker");
    let valid = KeyFactory::verify(&kp.public, &sig_bytes, tampered.as_bytes()).unwrap();
    assert!(!valid, "Tampered payload should fail verification");
}
