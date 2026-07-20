using System;

namespace ChatXdk
{
    /// <summary>
    /// Incremental stream encryptor for large payloads.
    ///
    /// <para>Feed plaintext with <see cref="Push"/>; call <see cref="Finish"/>
    /// once to emit the final frame. Always <see cref="Dispose"/> when finished.</para>
    /// </summary>
    public sealed unsafe class StreamEncryptor : IDisposable
    {
        private StreamEncryptorHandle* _handle;
        private bool _disposed;

        private StreamEncryptor(StreamEncryptorHandle* handle)
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
        ~StreamEncryptor() => Dispose(disposing: false);

        internal static StreamEncryptor Create(byte[] conversationKey)
        {
            var keyB64 = Chat.Utf8Z(Convert.ToBase64String(conversationKey));
            StreamEncryptorHandle* handle;
            fixed (byte* keyPtr = keyB64)
                handle = NativeMethods.chat_xdk_stream_encryptor_new(keyPtr);
            if (handle == null)
                throw new ChatXdkException("Invalid conversation key (expected 32 bytes)");
            return new StreamEncryptor(handle);
        }

        /// <summary>
        /// Encrypt a plaintext chunk, returning ciphertext available so far
        /// (may be empty for small inputs).
        /// </summary>
        public byte[] Push(byte[] plaintext)
        {
            ThrowIfDisposed();
            var ptB64 = Chat.Utf8Z(Convert.ToBase64String(plaintext));
            string resultB64;
            fixed (byte* ptPtr = ptB64)
                resultB64 = Chat.ConsumeResult(NativeMethods.chat_xdk_stream_encryptor_push(_handle, ptPtr));
            GC.KeepAlive(this);
            return Convert.FromBase64String(resultB64);
        }

        /// <summary>Emit the final frame and consume the encryptor.</summary>
        public byte[] Finish()
        {
            ThrowIfDisposed();
            var resultB64 = Chat.ConsumeResult(NativeMethods.chat_xdk_stream_encryptor_finish(_handle));
            GC.KeepAlive(this);
            return Convert.FromBase64String(resultB64);
        }

        private void ThrowIfDisposed()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(StreamEncryptor));
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
                NativeMethods.chat_xdk_stream_encryptor_free(_handle);
                _handle = null;
            }
        }
    }
}
