package com.x.chatxdk;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;

import java.util.Base64;

import com.x.chatxdk.Types.ImageDimensions;

/**
 * Stateless helpers (same semantics as Rust {@code chat_xdk_core::utils}).
 */
public final class ChatXdkUtilities {

    private ChatXdkUtilities() {}

    /** Encode bytes to standard base64. */
    public static String bytesToBase64(byte[] data) {
        if (data == null || data.length == 0) {
            return FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_bytes_to_base64(null, 0));
        }
        try (Memory m = new Memory(data.length)) {
            m.write(0, data, 0, data.length);
            return FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_bytes_to_base64(m, data.length));
        }
    }

    /** Decode standard base64 to bytes. */
    public static byte[] base64ToBytes(String b64) {
        try (Memory z = FfiStrings.utf8(b64)) {
            String innerB64 = FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_base64_to_bytes(z));
            return Base64.getDecoder().decode(innerB64);
        }
    }

    /** Encode bytes to lowercase hex. */
    public static String bytesToHex(byte[] data) {
        if (data == null || data.length == 0) {
            return FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_bytes_to_hex(null, 0));
        }
        try (Memory m = new Memory(data.length)) {
            m.write(0, data, 0, data.length);
            return FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_bytes_to_hex(m, data.length));
        }
    }

    /** Decode hex (even length) to bytes. */
    public static byte[] hexToBytes(String hex) {
        try (Memory z = FfiStrings.utf8(hex)) {
            String keyB64 = FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_hex_to_bytes(z));
            return Base64.getDecoder().decode(keyB64);
        }
    }

    /** Detect MIME type from magic bytes; returns {@code null} if unknown. */
    public static String detectMimeType(byte[] data) {
        String s;
        if (data == null || data.length == 0) {
            s = FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_detect_mime_type(null, 0));
        } else {
            try (Memory m = new Memory(data.length)) {
                m.write(0, data, 0, data.length);
                s = FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_detect_mime_type(m, data.length));
            }
        }
        return s.isEmpty() ? null : s;
    }

    /** Detect image dimensions from a header; returns {@code null} if unknown. */
    public static ImageDimensions detectImageDimensions(byte[] data) throws Exception {
        String s;
        if (data == null || data.length == 0) {
            s = FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_detect_image_dimensions(null, 0));
        } else {
            try (Memory m = new Memory(data.length)) {
                m.write(0, data, 0, data.length);
                s = FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_detect_image_dimensions(m, data.length));
            }
        }
        if ("null".equals(s)) {
            return null;
        }
        return ChatJson.MAPPER.readValue(s, ImageDimensions.class);
    }
}
