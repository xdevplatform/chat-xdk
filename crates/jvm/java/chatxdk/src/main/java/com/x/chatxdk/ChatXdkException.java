package com.x.chatxdk;

import com.fasterxml.jackson.databind.JsonNode;

/** Thrown when the SDK fails, with the {@link #getKind kind} of failure. */
public class ChatXdkException extends RuntimeException {

    /** What kind of failure a {@link ChatXdkException} is, the same in every binding. */
    public enum Kind {
        /** A parameter is missing or invalid; the message names it. */
        INVALID_INPUT,
        /** A value was neither passed nor available from the chat's state, such as no keys loaded. */
        INVALID_STATE,
        /** Event or other wire data is malformed. */
        PARSE,
        /** Ciphertext did not decrypt, or no key for it was available. */
        DECRYPTION,
        /** A signature did not verify, or could not be verified while unverified events are rejected. */
        VERIFICATION,
        /** Juicebox rejected the PIN; see {@link ChatXdkException#getGuessesRemaining}. */
        INVALID_PIN,
        /** Another Juicebox key-storage failure. */
        JUICEBOX,
        /** A failure inside the SDK. */
        INTERNAL,
    }

    private final Kind kind;
    private final Integer guessesRemaining;

    public ChatXdkException(Kind kind, String message, Integer guessesRemaining) {
        super(message);
        this.kind = kind;
        this.guessesRemaining = guessesRemaining;
    }

    public ChatXdkException(Kind kind, String message) {
        this(kind, message, null);
    }

    /** What kind of failure this is. */
    public Kind getKind() {
        return kind;
    }

    /**
     * The PIN attempts left after an {@link Kind#INVALID_PIN} failure, when Juicebox reports
     * them; {@code 0} means the guess budget is exhausted and the stored keys are locked.
     * {@code null} for every other failure.
     */
    public Integer getGuessesRemaining() {
        return guessesRemaining;
    }

    /** The exception for the native library's error document. */
    static ChatXdkException fromDocument(String document) {
        try {
            JsonNode root = ChatJson.MAPPER.readTree(document);
            Kind kind = switch (root.path("kind").asText()) {
                case "invalid_input" -> Kind.INVALID_INPUT;
                case "invalid_state" -> Kind.INVALID_STATE;
                case "parse" -> Kind.PARSE;
                case "decryption" -> Kind.DECRYPTION;
                case "verification" -> Kind.VERIFICATION;
                case "invalid_pin" -> Kind.INVALID_PIN;
                case "juicebox" -> Kind.JUICEBOX;
                default -> Kind.INTERNAL;
            };
            JsonNode guesses = root.get("guesses_remaining");
            return new ChatXdkException(
                    kind,
                    root.path("message").asText(),
                    guesses != null && guesses.canConvertToInt() ? guesses.intValue() : null);
        } catch (Exception e) {
            return new ChatXdkException(Kind.INTERNAL, document);
        }
    }
}
