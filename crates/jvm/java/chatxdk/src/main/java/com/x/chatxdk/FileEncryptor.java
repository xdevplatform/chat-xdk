package com.x.chatxdk;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.util.Base64;

/**
 * Incremental encryptor for one file of an outgoing message.
 *
 * <p>Feed the file with {@link #push}; call {@link #finish} once to emit the
 * final frame. Always {@link #close} the instance to release native resources.
 *
 * <p>Not thread-safe: do not share one instance across threads without external
 * synchronization.
 */
public final class FileEncryptor implements AutoCloseable {

    /**
     * Frees a native file-encryptor handle (which holds live secretstream key
     * state). Registered with the shared cleaner; the cleaner runs a registered
     * action at most once, so an explicit {@code close()} and the GC backstop
     * can never double-free.
     *
     * <p>An object becomes phantom-reachable as soon as its last use passes —
     * even while one of its methods is still executing native code — so every
     * method that passes {@code handle} to the native library calls
     * {@link Reference#reachabilityFence} on {@code this} in a {@code finally}
     * block, keeping the cleaner from freeing the handle mid-call.
     */
    private static final class FreeHandle implements Runnable {
        private final Pointer handle;

        FreeHandle(Pointer handle) {
            this.handle = handle;
        }

        @Override
        public void run() {
            ChatNative.INSTANCE.chat_xdk_file_encryptor_free(handle);
        }
    }

    private Pointer handle;
    private boolean closed;
    private final Cleaner.Cleanable cleanable;

    private FileEncryptor(Pointer handle) {
        this.handle = handle;
        this.cleanable = Chat.CLEANER.register(this, new FreeHandle(handle));
    }

    static FileEncryptor create(Pointer chatHandle, String paramsJson) {
        try (Memory params = FfiStrings.utf8(paramsJson)) {
            PointerByReference out = new PointerByReference();
            FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_file_encryptor_new(chatHandle, params, out));
            return new FileEncryptor(out.getValue());
        }
    }

    /**
     * Encrypt a chunk of the file, returning the encrypted bytes available so
     * far (may be empty for small inputs).
     */
    public byte[] push(byte[] plaintext) {
        throwIfClosed();
        try (Memory pt = FfiStrings.utf8(Base64.getEncoder().encodeToString(plaintext))) {
            String resultB64 =
                    FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_file_encryptor_push(handle, pt));
            return Base64.getDecoder().decode(resultB64);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /** Emit the final frame and consume the encryptor. */
    public byte[] finish() {
        throwIfClosed();
        try {
            String resultB64 =
                    FfiStrings.consume(ChatNative.INSTANCE.chat_xdk_file_encryptor_finish(handle));
            return Base64.getDecoder().decode(resultB64);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    private void throwIfClosed() {
        if (closed) {
            throw new IllegalStateException("FileEncryptor is closed");
        }
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            handle = null;
            cleanable.clean();
        }
    }
}
