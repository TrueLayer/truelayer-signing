using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace TrueLayer.Signing
{
    /// <summary>Sign/verification error.</summary>
    public sealed class SignatureException : Exception
    {
        internal static void Ensure(bool condition, string failMessage)
        {
            if (!condition)
            {
                throw new SignatureException(failMessage);
            }
        }

        /// <summary>
        /// Run the function converting any thrown exception into a SignatureException.
        /// </summary>
        internal static T Try<T>(Func<T> f, string? message = null)
        {
            try
            {
                return f();
            }
            catch (SignatureException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new SignatureException(message ?? e.Message ?? e.GetType().Name, e);
            }
        }

        /// <summary>
        /// Run the action converting any thrown exception into a SignatureException.
        /// </summary>
        internal static void TryAction(Action f, string? message = null)
        {
            Try(() =>
            {
                f();
                return (object?)null;
            }, message);
        }

        internal SignatureException(string message) : base(message) { }
        internal SignatureException(string message, Exception? innerException) : base(message, innerException) { }
    }

    internal static class Util
    {
        /// <summary>
        /// Build signing payload from method, path, some/none/all headers and body.
        /// </summary>
        internal static byte[] BuildV2SigningPayload(
            string method,
            string path,
            List<(string, byte[])> headers,
            byte[] body)
        {
            var payload = new List<byte>();
            payload.AddRange(method.ToUpperInvariant().ToUtf8());
            payload.AddRange(" ".ToUtf8());
            payload.AddRange(path.ToUtf8());
            payload.AddRange("\n".ToUtf8());
            foreach (var (name, value) in headers)
            {
                payload.AddRange(name.ToUtf8());
                payload.AddRange(": ".ToUtf8());
                payload.AddRange(value);
                payload.AddRange("\n".ToUtf8());
            }
            payload.AddRange(body);
            return payload.ToArray();
        }

        /// <summary>Convert to utf-8 bytes</summary>
        internal static byte[] ToUtf8(this string text) => Encoding.UTF8.GetBytes(text);

        /// <summary>Parses a RFC 7468 PEM-encoded key into a `ECDsa`.</summary>
        internal static ECDsa ParsePem(this ReadOnlySpan<char> pem)
        {
            var ecdsa = ECDsa.Create();
#if (NET5_0 || NET5_0_OR_GREATER)
            ecdsa.ImportFromPem(pem);
#else
            ecdsa.PreNet5ImportPem(pem);
#endif
            return ecdsa;
        }

        /// <summary>
        /// Imports an RFC 7468 PEM-encoded key, replacing the keys for this object.
        /// </summary>
        private static void PreNet5ImportPem(this ECDsa key, ReadOnlySpan<char> pem)
        {
            try
            {
#if (NETSTANDARD2_0)
                key.BouncyCastleImportPem(pem);
#else
                var sb = new StringBuilder();
                using (var reader = new StringReader(pem.ToString()))
                {
                    string? line = null;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (!line.StartsWith("--"))
                        {
                            sb.Append(line);
                        }
                    }
                }
                var decodedPem = Convert.FromBase64String(sb.ToString());
                if (pem.Contains("PRIVATE KEY-----", StringComparison.InvariantCulture))
                {
                    key.ImportECPrivateKey(decodedPem, out _);
                }
                else
                {
                    key.ImportSubjectPublicKeyInfo(decodedPem, out _);
                }
#endif
            }
            catch (Exception e)
            {
                // throw somewhat consistently with `ImportFromPem`.
                throw new ArgumentException($"Invalid key pem data: {e.Message}");
            }
        }

        /// <summary>Gets a value from the map as a string or null.</summary>
        public static string? GetString(this IDictionary<string, object> dict, string key)
        {
            if (dict.TryGetValue(key, out var value))
            {
                return value as string;
            }
            return null;
        }

        /// <summary>
        /// Returns a new byte array prepended with zeros up to the given length.
        /// Returns the input array unchanged if already at, or above, the length.
        /// </summary>
        public static byte[] PrependZeroPad(this byte[] bytes, int length)
        {
            if (bytes.Length >= length)
            {
                return bytes;
            }
            var padded = new byte[length];
            Array.Copy(bytes, 0, padded, 1, bytes.Length);
            return padded;
        }
    }

    /// <summary>Case-insensitive string header name comparison.</summary>
    internal class HeaderNameComparer : IEqualityComparer<string>
    {
        public bool Equals(string? x, string? y)
            => string.Equals(x, y, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode(string x) => x.ToLowerInvariant().GetHashCode();
    }

    /// <summary>JWKs json object.</summary>
    internal class Jwks
    {
        public List<Jwk> Keys { get; set; } = new List<Jwk>();
    }

    internal class Jwk
    {
        public string Kid { get; set; } = "";
        public string Kty { get; set; } = "";
        public string Alg { get; set; } = "";
        public string Crv { get; set; } = "";
        public string X { get; set; } = "";
        public string Y { get; set; } = "";
    }
}
