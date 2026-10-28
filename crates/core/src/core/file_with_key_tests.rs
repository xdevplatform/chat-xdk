//! `encrypt_file_with_key` and `decrypt_file_with_key`: a file under a key the
//! caller holds, in the secretstream format files take.

use super::*;
use crate::error::ErrorKind;
use crate::utils::encrypted_file_size;

const KEY: [u8; 32] = [7; 32];
const HEADER: usize = 24;
const FRAME: usize = 1024 + 17;

fn encrypt(file: &[u8], key: &[u8]) -> Result<Vec<u8>, SdkError> {
    ChatCore::new()
        .encrypt_file_with_key(&EncryptFileWithKeyParams::new(file.to_vec(), key.to_vec()))
}

fn decrypt(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, SdkError> {
    ChatCore::new().decrypt_file_with_key(&DecryptFileWithKeyParams::new(
        encrypted.to_vec(),
        key.to_vec(),
    ))
}

fn file_of(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

#[test]
fn files_of_every_frame_count_round_trip() {
    // Empty, inside one frame, exactly one and two frames, and a short last
    // frame.
    for size in [0, 1, 1023, 1024, 1025, 2048, 3050] {
        let file = file_of(size);
        let encrypted = encrypt(&file, &KEY).unwrap();
        assert_eq!(
            Some(encrypted.len() as u64),
            encrypted_file_size(size as u64),
            "size {size}"
        );
        assert_eq!(decrypt(&encrypted, &KEY).unwrap(), file, "size {size}");
    }
}

#[test]
fn an_empty_file_is_the_header_alone() {
    let encrypted = encrypt(&[], &KEY).unwrap();
    assert_eq!(encrypted.len(), HEADER);
    assert!(decrypt(&encrypted, &KEY).unwrap().is_empty());
}

#[test]
fn frames_are_1024_bytes_with_the_final_tag_on_the_last() {
    // Pull the frames with the secretstream primitive itself: no associated
    // data, a message tag on every frame but the last.
    use crypto_secretstream::{Header, Key, PullStream, Tag};
    for size in [1024, 2048, 3050] {
        let file = file_of(size);
        let encrypted = encrypt(&file, &KEY).unwrap();
        let (header, frames) = encrypted.split_at(HEADER);
        let header: [u8; HEADER] = header.try_into().unwrap();
        let mut pull = PullStream::init(Header::from(header), &Key::from(KEY));
        let frames: Vec<&[u8]> = frames.chunks(FRAME).collect();
        assert_eq!(frames.len(), size.div_ceil(1024), "size {size}");
        let mut opened = Vec::new();
        for (i, frame) in frames.iter().enumerate() {
            let mut frame = frame.to_vec();
            let tag = pull.pull(&mut frame, &[]).unwrap();
            let last = i + 1 == frames.len();
            assert!(
                tag == if last { Tag::Final } else { Tag::Message },
                "size {size} frame {i}"
            );
            opened.extend_from_slice(&frame);
        }
        assert_eq!(opened, file, "size {size}");
    }
}

#[test]
fn files_cross_with_the_crypto_module_functions() {
    let key = XChatConversationKey::from_bytes(KEY.to_vec()).unwrap();
    let file = file_of(2600);

    let mut from_module = Vec::new();
    crate::crypto::encryption::encrypt_file(&key, file.as_slice(), &mut from_module).unwrap();
    assert_eq!(decrypt(&from_module, &KEY).unwrap(), file);

    let from_call = encrypt(&file, &KEY).unwrap();
    let mut opened = Vec::new();
    crate::crypto::encryption::decrypt_file(&key, from_call.as_slice(), &mut opened).unwrap();
    assert_eq!(opened, file);
}

/// X Android encrypts a group avatar with the raw conversation key in this
/// format (x-android LibsodiumEncryption.kt `encryptStream`, called from
/// ConversationManagerImpl.kt `uploadAvatar`), under the key whose version
/// its avatar change signs. The image here is the avatar-shaped file of the
/// 0.5.x fixtures: JPEG markers around 3,028 filler bytes.
#[test]
fn an_avatar_under_the_conversation_key_round_trips() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/compat_v0_5_2.json"
    ))
    .unwrap();
    let field = |key: &str| base64_decode(fixture["avatar_file"][key].as_str().unwrap()).unwrap();
    let conversation_key =
        base64_decode(fixture["conversation_key_b64"].as_str().unwrap()).unwrap();
    let avatar = field("plaintext_b64");
    assert_eq!(&avatar[..3], b"\xff\xd8\xff");

    let encrypted = encrypt(&avatar, &conversation_key).unwrap();
    assert_eq!(encrypted.len(), field("ciphertext_b64").len());
    assert_ne!(
        encrypted,
        field("ciphertext_b64"),
        "each file takes a fresh header"
    );
    assert_eq!(decrypt(&encrypted, &conversation_key).unwrap(), avatar);
    assert_eq!(
        decrypt(&field("ciphertext_b64"), &conversation_key).unwrap(),
        avatar
    );
}

#[test]
fn a_key_that_is_not_32_bytes_is_invalid_input() {
    let encrypted = encrypt(b"file", &KEY).unwrap();
    for len in [0, 16, 31, 33, 64] {
        let key = vec![1u8; len];
        for err in [
            encrypt(b"file", &key).unwrap_err(),
            decrypt(&encrypted, &key).unwrap_err(),
        ] {
            assert_eq!(err.kind(), ErrorKind::InvalidInput, "{len}: {err}");
            assert!(
                err.to_string().contains(&format!("got {len}")),
                "{len}: {err}"
            );
        }
    }
}

#[test]
fn a_bad_or_truncated_file_is_a_decryption_error() {
    let file = file_of(2500);
    let encrypted = encrypt(&file, &KEY).unwrap();
    let mut flipped = encrypted.clone();
    flipped[100] ^= 1;
    let mut trailing = encrypted.clone();
    trailing.push(0);
    let cases = [
        ("another key's file", encrypt(&file, &[9; 32]).unwrap()),
        ("a flipped byte", flipped),
        (
            "cut inside the last frame",
            encrypted[..encrypted.len() - 1].to_vec(),
        ),
        (
            "cut at a frame boundary",
            encrypted[..HEADER + FRAME].to_vec(),
        ),
        ("cut inside the header", encrypted[..10].to_vec()),
        ("bytes after the final frame", trailing),
    ];
    for (case, bytes) in cases {
        let err = decrypt(&bytes, &KEY).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Decryption, "{case}: {err}");
        assert!(
            err.to_string()
                .contains("not a complete file encrypted under this key"),
            "{case}: {err}"
        );
    }
}

#[test]
fn a_header_alone_decrypts_to_an_empty_file_under_any_key() {
    let encrypted = encrypt(&file_of(2500), &KEY).unwrap();
    for (case, bytes) in [
        ("cut at the end of the header", encrypted[..HEADER].to_vec()),
        ("another key's empty file", encrypt(&[], &[9; 32]).unwrap()),
        ("24 zero bytes", vec![0; HEADER]),
    ] {
        assert_eq!(decrypt(&bytes, &KEY).unwrap(), Vec::<u8>::new(), "{case}");
    }
}

#[test]
fn the_params_redact_the_key() {
    let encrypt = format!(
        "{:?}",
        EncryptFileWithKeyParams::new(vec![1; 5], vec![42; 32])
    );
    let decrypt = format!(
        "{:?}",
        DecryptFileWithKeyParams::new(vec![1; 5], vec![42; 32])
    );
    for debug in [encrypt, decrypt] {
        assert!(debug.contains("[REDACTED]"), "{debug}");
        assert!(debug.contains("[5 bytes]"), "{debug}");
        assert!(!debug.contains("42"), "{debug}");
    }
}
