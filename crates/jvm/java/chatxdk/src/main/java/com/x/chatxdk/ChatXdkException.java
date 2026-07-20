package com.x.chatxdk;

/** Thrown when the native chat-xdk library returns an error string. */
public class ChatXdkException extends RuntimeException {
    public ChatXdkException(String message) {
        super(message);
    }
}
