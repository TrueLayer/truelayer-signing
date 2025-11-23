using System;

namespace TrueLayer.Signing
{
    /// <summary>Internal Base64Url encoding/decoding for AOT compatibility.</summary>
    internal static class Base64Url
    {
        /// <summary>Encode bytes to base64url string.</summary>
        public static string Encode(byte[] input) => Convert.ToBase64String(input).Split('=')[0].Replace('+', '-').Replace('/', '_');

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