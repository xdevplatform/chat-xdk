package com.example.chatbot;

import com.x.chatxdk.PublicKeyResolver;

import java.util.concurrent.ConcurrentHashMap;

/**
 * One chat per signed-in user, all fetching public keys with one resolver.
 *
 * <p>A chat holds one user's private keys and signs as that user. A process
 * that serves several signed-in users keeps one chat per user, for all of
 * that user's conversations, and never one per conversation: the chat keeps
 * its conversation keys by conversation and the public keys it has met by
 * user id.
 *
 * <p>It may be called from several threads at once.
 */
public final class UserChats {

    private final PublicKeyResolver resolver;

    /** The chats, by user id. Its {@code computeIfAbsent} creates a user's chat once. */
    private final ConcurrentHashMap<String, ChatCore> chats = new ConcurrentHashMap<>();

    /** {@code resolver} is the resolver every chat shares: a {@link SharedPublicKeys}. */
    public UserChats(PublicKeyResolver resolver) {
        this.resolver = resolver;
    }

    /**
     * The chat of the signed-in user {@code userId}, created on first use from
     * the user's private-key blob and the {@code public_key_version} it was
     * registered under. Calls for one user get the same chat, also from
     * several threads, and that chat serves every conversation of the user.
     * A chat that could not be created is not kept: the next call tries again.
     */
    public ChatCore chatFor(String userId, String privateKeysB64, String signingKeyVersion) {
        return chats.computeIfAbsent(userId, id -> open(id, privateKeysB64, signingKeyVersion));
    }

    private ChatCore open(String userId, String privateKeysB64, String signingKeyVersion) {
        ChatCore core = new ChatCore();
        try {
            core.loadKeys(privateKeysB64, signingKeyVersion);
            core.setIdentity(userId);
            core.resolvePublicKeysWith(resolver);
        } catch (RuntimeException e) {
            core.close();
            throw e;
        }
        return core;
    }

    /**
     * Sign {@code userId} out: forget the user's chat and clear its keys from
     * memory. No call on that chat may be running, and none may follow.
     */
    public void close(String userId) {
        ChatCore chat = chats.remove(userId);
        if (chat != null) {
            chat.close();
        }
    }
}
