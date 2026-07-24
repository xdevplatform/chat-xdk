package com.x.chatxdk;

import com.sun.jna.Library;
import com.sun.jna.Pointer;

/**
 * JNA mapping to the {@code chat_xdk_dotnet} cdylib.
 *
 * <p>Loaded via {@link NativeLoader}: embedded multi-arch natives from the published JAR when
 * present, otherwise {@code jna.library.path} / system library search (local development).
 */
public interface ChatNative extends Library {

    ChatNative INSTANCE = NativeLoader.load();

    Pointer chat_xdk_new();

    void chat_xdk_free(Pointer handle);

    void chat_xdk_free_string(Pointer s);

    int chat_xdk_is_unlocked(Pointer handle);

    int chat_xdk_has_identity_key(Pointer handle);

    void chat_xdk_set_reject_unverified(Pointer handle, int reject);

    FfiResult.ByValue chat_xdk_set_identity(Pointer handle, Pointer userId, Pointer signingKeyVersion);

    void chat_xdk_set_cache_keys(Pointer handle, int enabled);

    FfiResult.ByValue chat_xdk_set_signing_keys(Pointer handle, Pointer signingKeysJson);

    void chat_xdk_lock(Pointer handle);

    FfiResult.ByValue chat_xdk_update_config(Pointer handle, Pointer configJson);

    FfiResult.ByValue chat_xdk_setup(Pointer handle, Pointer pin, Pointer configJson);

    FfiResult.ByValue chat_xdk_unlock(Pointer handle, Pointer pin, Pointer configJson);

    FfiResult.ByValue chat_xdk_delete(Pointer handle);

    FfiResult.ByValue chat_xdk_change_pin(Pointer handle, Pointer oldPin, Pointer newPin);

    FfiResult.ByValue chat_xdk_generate_keypairs(Pointer handle);

    FfiResult.ByValue chat_xdk_get_public_keys(Pointer handle);

    FfiResult.ByValue chat_xdk_get_public_key_fingerprint(Pointer handle);

    FfiResult.ByValue chat_xdk_export_keys(Pointer handle);

    FfiResult.ByValue chat_xdk_import_keys(Pointer handle, Pointer keysB64);

    FfiResult.ByValue chat_xdk_import_keys_with_version(
            Pointer handle, Pointer keys, long keysLen, Pointer version);

    FfiResult.ByValue chat_xdk_extract_conversation_keys(Pointer handle, Pointer eventsJson);

    FfiResult.ByValue chat_xdk_decrypt_events(Pointer handle, Pointer eventsJson, Pointer signingKeysJson);

    FfiResult.ByValue chat_xdk_prepare_conversation_key_change(Pointer handle, Pointer paramsJson);

    FfiResult.ByValue chat_xdk_prepare_group_members_change(Pointer handle, Pointer paramsJson);

    FfiResult.ByValue chat_xdk_prepare_group_create(Pointer handle, Pointer paramsJson);

    FfiResult.ByValue chat_xdk_prepare_message_delete(Pointer handle, Pointer paramsJson);

    FfiResult.ByValue chat_xdk_decrypt_event(
            Pointer handle, Pointer eventB64, Pointer conversationKeysJson, Pointer signingKeysJson);

    FfiResult.ByValue chat_xdk_encrypt_message(Pointer handle, Pointer paramsJson);

    FfiResult.ByValue chat_xdk_encrypt_reply(Pointer handle, Pointer paramsJson);

    FfiResult.ByValue chat_xdk_encrypt_add_reaction(Pointer handle, Pointer paramsJson);

    FfiResult.ByValue chat_xdk_encrypt_remove_reaction(Pointer handle, Pointer paramsJson);

    FfiResult.ByValue chat_xdk_encrypt_edit(Pointer handle, Pointer paramsJson);

    FfiResult.ByValue chat_xdk_decrypt_conversation_key(Pointer handle, Pointer encryptedKeyB64);

    FfiResult.ByValue chat_xdk_encrypt(Pointer handle, Pointer plaintext, Pointer conversationKeyB64);

    FfiResult.ByValue chat_xdk_decrypt(Pointer handle, Pointer ciphertextB64, Pointer conversationKeyB64);

    FfiResult.ByValue chat_xdk_decrypt_stream(Pointer handle, Pointer encryptedB64, Pointer conversationKeyB64);

    FfiResult.ByValue chat_xdk_encrypt_stream(Pointer handle, Pointer plaintextB64, Pointer conversationKeyB64);

    Pointer chat_xdk_stream_encryptor_new(Pointer conversationKeyB64);

    FfiResult.ByValue chat_xdk_stream_encryptor_push(Pointer handle, Pointer plaintextB64);

    FfiResult.ByValue chat_xdk_stream_encryptor_finish(Pointer handle);

    void chat_xdk_stream_encryptor_free(Pointer handle);

    Pointer chat_xdk_stream_decryptor_new(Pointer conversationKeyB64);

    FfiResult.ByValue chat_xdk_stream_decryptor_push(Pointer handle, Pointer ciphertextB64);

    FfiResult.ByValue chat_xdk_stream_decryptor_finish(Pointer handle);

    void chat_xdk_stream_decryptor_free(Pointer handle);

    FfiResult.ByValue chat_xdk_sign(Pointer handle, Pointer data, long dataLen);

    int chat_xdk_verify(Pointer handle, Pointer publicKeyB64, Pointer signatureB64, Pointer data, long dataLen);

    int chat_xdk_verify_key_binding(Pointer handle, Pointer identityPublicKeyB64, Pointer signingPublicKeyB64, Pointer identityPublicKeySignatureB64);

    int chat_xdk_matches_registered_key(Pointer handle, Pointer publicKeyB64);

    FfiResult.ByValue chat_xdk_bytes_to_base64(Pointer data, long dataLen);

    FfiResult.ByValue chat_xdk_base64_to_bytes(Pointer b64);

    FfiResult.ByValue chat_xdk_bytes_to_hex(Pointer data, long dataLen);

    FfiResult.ByValue chat_xdk_hex_to_bytes(Pointer hex);

    FfiResult.ByValue chat_xdk_detect_mime_type(Pointer data, long dataLen);

    FfiResult.ByValue chat_xdk_detect_image_dimensions(Pointer data, long dataLen);
}
