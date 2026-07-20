package com.x.chatxdk;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;

import java.nio.charset.StandardCharsets;

/** UTF-8 nul-terminated strings and {@link FfiResult} consumption. */
final class FfiStrings {

    private FfiStrings() {}

    static Memory utf8(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        Memory m = new Memory(bytes.length + 1L);
        m.write(0, bytes, 0, bytes.length);
        m.setByte(bytes.length, (byte) 0);
        return m;
    }

    static String readUtf8(Pointer p) {
        if (p == null) {
            return null;
        }
        return p.getString(0, "UTF-8");
    }

    /**
     * Frees native strings in {@code result} and returns data (or empty string for void OK).
     *
     * @throws ChatXdkException if {@code error} was non-null
     */
    static String consume(FfiResult.ByValue result) {
        String data = readUtf8(result.data);
        String error = readUtf8(result.error);
        if (result.data != null) {
            ChatNative.INSTANCE.chat_xdk_free_string(result.data);
        }
        if (result.error != null) {
            ChatNative.INSTANCE.chat_xdk_free_string(result.error);
        }
        if (error != null) {
            throw new ChatXdkException(error);
        }
        return data == null ? "" : data;
    }
}
