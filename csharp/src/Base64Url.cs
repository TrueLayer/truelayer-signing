using System;

namespace TrueLayer.Signing
{
    /// <summary>Internal Base64Url encoding/decoding for AOT compatibility.</summary>
    internal static class Base64Url
    {
        /// <summary>Encode bytes to base64url string.</summary>
        public static string Encode(byte[] input)
        {
            if (input is null)
            {
                throw new ArgumentNullException(nameof(input));
            }

#if NET9_0_OR_GREATER
            return System.Buffers.Text.Base64Url.EncodeToString(input);
#else
            // One char buffer and one string, instead of a new string per TrimEnd/Replace
            var chars = new char[(input.Length + 2) / 3 * 4];
            var length = Convert.ToBase64CharArray(input, 0, input.Length, chars, 0);
            while (length > 0 && chars[length - 1] == '=')
            {
                length--;
            }

            for (var i = 0; i < length; i++)
            {
                if (chars[i] == '+')
                {
                    chars[i] = '-';
                }
                else if (chars[i] == '/')
                {
                    chars[i] = '_';
                }
            }

            return new string(chars, 0, length);
#endif
        }

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
