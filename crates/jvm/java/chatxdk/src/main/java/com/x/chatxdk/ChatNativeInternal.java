package com.x.chatxdk;

import com.sun.jna.Library;
import com.sun.jna.Pointer;

/** JNA mapping of {@code chat_xdk_dotnet} entry points used only inside this package. */
interface ChatNativeInternal extends Library {

    ChatNativeInternal INSTANCE = NativeLoader.loadInternal(ChatNativeInternal.class);

    Pointer chat_xdk_stream_decryptor_new_with_chat(Pointer chatHandle, Pointer conversationKeyB64);
}
