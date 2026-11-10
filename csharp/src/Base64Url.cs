using System;

namespace TrueLayer.Signing
{
    /// <summary>Internal Base64Url encoding/decoding for AOT compatibility.</summary>
    internal static class Base64Url
    {
        /// <summary>Encode bytes to base64url string.</summary>
        public static string Encode(byte[] input)
#if NET9_0_OR_GREATER
            => System.Buffers.Text.Base64Url.EncodeToString(input ?? throw new ArgumentNullException(nameof(input)));
#else
            => Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
#endif

        /// <summary>Decode base64url string to bytes.</summary>
        public static byte[] Decode(string input)
        {
            var base64 = input.Replace('-', '+').Replace('_', '/');
            switch (input.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            return Convert.FromBase64String(base64);
        }
    }
}
