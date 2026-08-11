package com.x.chatxdk;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Thrown when the native chat-xdk library returns an error string. */
public class ChatXdkException extends RuntimeException {

    /**
     * Stable invalid-PIN message form the core emits ("Invalid PIN: guesses_remaining=N").
     * Anchored on the full form so a count embedded in an unrelated pass-through message is
     * not misread.
     */
    private static final Pattern GUESSES_REMAINING =
            Pattern.compile("\\bInvalid PIN: guesses_remaining=(\\d+)");

    public ChatXdkException(String message) {
        super(message);
    }

    /**
     * Remaining PIN attempts reported by Juicebox, or {@code null} when the message carries no
     * count.
     *
     * <p>Present only on invalid-PIN {@link Chat#unlock} / {@link Chat#changePin} failures.
     * {@code 0} means the guess budget is exhausted and the stored keys are locked.
     */
    public Integer getGuessesRemaining() {
        String message = getMessage();
        if (message == null) {
            return null;
        }
        Matcher m = GUESSES_REMAINING.matcher(message);
        if (!m.find()) {
            return null;
        }
        try {
            return Integer.valueOf(m.group(1));
        } catch (NumberFormatException e) {
            // Digits too large for an int — treat as no usable count.
            return null;
        }
    }
}
