using System;

namespace ChatXdk
{
    /// <summary>
    /// Incremental stream decryptor for large payloads.
    ///
    /// <para>Feed ciphertext with <see cref="Push"/>; call <see cref="Finish"/>
    /// once at end of input. <see cref="Finish"/> throws if the stream ended
    /// before its final frame (truncation), so do not treat plaintext from
    /// <see cref="Push"/> as complete until <see cref="Finish"/> succeeds.
    /// Always <see cref="Dispose"/> when finished.</para>
    /// </summary>
    public sealed unsafe class StreamDecryptor : IDisposable
    {
        private StreamDecryptorHandle* _handle;
        private bool _disposed;

        private StreamDecryptor(StreamDecryptorHandle* handle)
        {
            _handle = handle;
        }

        /// <summary>
        /// Finalizer — frees the native handle (which holds live secretstream key
        /// state) even if <see cref="Dispose"/> is never called explicitly.
        /// An object becomes finalizable as soon as its last use passes — even while
        /// one of its methods is still executing native code — so every method that
        /// passes <c>_handle</c> across the P/Invoke boundary calls
        /// <see cref="GC.KeepAlive(object)"/> on <c>this</c> after the call, keeping
        /// this finalizer from freeing the handle mid-call.
        /// </summary>
        ~StreamDecryptor() => Dispose(disposing: false);

        internal static StreamDecryptor Create(byte[] conversationKey)
        {
            var keyB64 = Chat.Utf8Z(Convert.ToBase64String(conversationKey));
            StreamDecryptorHandle* handle;
            fixed (byte* keyPtr = keyB64)
                handle = NativeMethods.chat_xdk_stream_decryptor_new(keyPtr);
            if (handle == null)
                throw new ChatXdkException("Invalid conversation key (expected 32 bytes)");
            return new StreamDecryptor(handle);
        }

        /// <summary>
        /// Decrypt a ciphertext chunk, returning plaintext available so far
        /// (may be empty until enough input has arrived).
        /// </summary>
        public byte[] Push(byte[] ciphertext)
        {
            ThrowIfDisposed();
            var ctB64 = Chat.Utf8Z(Convert.ToBase64String(ciphertext));
            string resultB64;
            fixed (byte* ctPtr = ctB64)
                resultB64 = Chat.ConsumeResult(NativeMethods.chat_xdk_stream_decryptor_push(_handle, ctPtr));
            GC.KeepAlive(this);
            return Convert.FromBase64String(resultB64);
        }

        /// <summary>Decrypt the final frame and consume the decryptor.</summary>
        public byte[] Finish()
        {
            ThrowIfDisposed();
            var resultB64 = Chat.ConsumeResult(NativeMethods.chat_xdk_stream_decryptor_finish(_handle));
            GC.KeepAlive(this);
            return Convert.FromBase64String(resultB64);
        }

        private void ThrowIfDisposed()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(StreamDecryptor));
        }

        /// <summary>Release the native handle.</summary>
        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            // Both the finalizer and Dispose() paths end here; only the
            // unmanaged handle needs freeing.
            if (_disposed) return;
            _disposed = true;
            if (_handle != null)
            {
                NativeMethods.chat_xdk_stream_decryptor_free(_handle);
                _handle = null;
            }
        }
    }
}
