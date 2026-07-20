using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ChatXdk
{
    /// <summary>
    /// Stateless helpers (same semantics as Rust <c>chat_xdk_core::utils</c>).
    /// </summary>
    public static unsafe class ChatXdkUtilities
    {
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        private static string Consume(FfiResult result)
        {
            string? data = result.data != null
                ? Marshal.PtrToStringUTF8((IntPtr)result.data)
                : null;
            string? error = result.error != null
                ? Marshal.PtrToStringUTF8((IntPtr)result.error)
                : null;

            if (result.data != null) NativeMethods.chat_xdk_free_string(result.data);
            if (result.error != null) NativeMethods.chat_xdk_free_string(result.error);

            if (error != null) throw new ChatXdkException(error);
            return data ?? "";
        }

        private static byte[] Utf8Z(string s)
        {
            int len = Encoding.UTF8.GetByteCount(s);
            byte[] buf = new byte[len + 1];
            Encoding.UTF8.GetBytes(s, 0, s.Length, buf, 0);
            return buf;
        }

        /// <summary>Encode bytes to standard base64.</summary>
        public static string BytesToBase64(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty)
                return Consume(NativeMethods.chat_xdk_bytes_to_base64(null, 0));
            fixed (byte* p = data)
                return Consume(NativeMethods.chat_xdk_bytes_to_base64(p, (nuint)data.Length));
        }

        /// <summary>Decode standard base64 to bytes.</summary>
        public static byte[] Base64ToBytes(string b64)
        {
            var z = Utf8Z(b64);
            fixed (byte* p = z)
            {
                string innerB64 = Consume(NativeMethods.chat_xdk_base64_to_bytes(p));
                return Convert.FromBase64String(innerB64);
            }
        }

        /// <summary>Encode bytes to lowercase hex.</summary>
        public static string BytesToHex(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty)
                return Consume(NativeMethods.chat_xdk_bytes_to_hex(null, 0));
            fixed (byte* p = data)
                return Consume(NativeMethods.chat_xdk_bytes_to_hex(p, (nuint)data.Length));
        }

        /// <summary>Decode hex (even length) to bytes.</summary>
        public static byte[] HexToBytes(string hex)
        {
            var z = Utf8Z(hex);
            fixed (byte* p = z)
            {
                string keyB64 = Consume(NativeMethods.chat_xdk_hex_to_bytes(p));
                return Convert.FromBase64String(keyB64);
            }
        }

        /// <summary>Detect MIME type from magic bytes; returns <c>null</c> if unknown.</summary>
        public static string? DetectMimeType(ReadOnlySpan<byte> data)
        {
            string s;
            if (data.IsEmpty)
                s = Consume(NativeMethods.chat_xdk_detect_mime_type(null, 0));
            else
            {
                fixed (byte* p = data)
                    s = Consume(NativeMethods.chat_xdk_detect_mime_type(p, (nuint)data.Length));
            }
            return s.Length == 0 ? null : s;
        }

        /// <summary>Detect image dimensions from a header; returns <c>null</c> if unknown.</summary>
        public static ImageDimensions? DetectImageDimensions(ReadOnlySpan<byte> data)
        {
            string s;
            if (data.IsEmpty)
                s = Consume(NativeMethods.chat_xdk_detect_image_dimensions(null, 0));
            else
            {
                fixed (byte* p = data)
                    s = Consume(NativeMethods.chat_xdk_detect_image_dimensions(p, (nuint)data.Length));
            }
            if (s == "null") return null;
            return JsonSerializer.Deserialize<ImageDimensions>(s, JsonOpts);
        }
    }
}
