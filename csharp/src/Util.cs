using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

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
        // Cache frequently-used UTF8 byte sequences to avoid repeated encoding
        private static readonly byte[] SpaceBytes = Encoding.UTF8.GetBytes(" ");
        private static readonly byte[] NewlineBytes = Encoding.UTF8.GetBytes("\n");
        private static readonly byte[] ColonSpaceBytes = Encoding.UTF8.GetBytes(": ");

        /// <summary>
        /// Build signing payload from method, path, some/none/all headers and body.
        /// </summary>
        internal static byte[] BuildV2SigningPayload(
            string method,
            string path,
            IEnumerable<(string, byte[])> headers,
            byte[] body)
        {
            var payload = new List<byte>();
            payload.AddRange(method.ToUpperInvariant().ToUtf8());
            payload.AddRange(SpaceBytes);
            payload.AddRange(path.ToUtf8());
            payload.AddRange(NewlineBytes);
            foreach (var (name, value) in headers)
            {
                payload.AddRange(name.ToUtf8());
                payload.AddRange(ColonSpaceBytes);
                payload.AddRange(value);
                payload.AddRange(NewlineBytes);
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
        public static string? GetString(this Dictionary<string, JsonElement> dict, string key)
        {
            if (!dict.TryGetValue(key, out var element))
            {
                return null;
            }

            if (element.ValueKind == JsonValueKind.String)
            {
                return element.GetString();
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

        /// <summary>
        /// Builds the JWS signing input in the format "base64url(header).base64url(payload)"
        /// and computes the SHA-512 hash for ES512 signing/verification.
        /// </summary>
        /// <param name="headerB64">Base64url-encoded JWS header</param>
        /// <param name="payloadB64">Base64url-encoded payload</param>
        /// <returns>SHA-512 hash of the signing input</returns>
        internal static byte[] ComputeJwsSigningHash(string headerB64, string payloadB64)
        {
            // Build the signing input: base64url(header).base64url(payload)
            var signingInput = new byte[headerB64.Length + 1 + payloadB64.Length];
#if NET5_0_OR_GREATER
            // Use Span-based API for better performance on modern .NET
            Encoding.ASCII.GetBytes(headerB64, signingInput.AsSpan(0, headerB64.Length));
            signingInput[headerB64.Length] = (byte)'.';
            Encoding.ASCII.GetBytes(payloadB64, signingInput.AsSpan(headerB64.Length + 1));
#else
            Encoding.ASCII.GetBytes(headerB64, 0, headerB64.Length, signingInput, 0);
            signingInput[headerB64.Length] = (byte)'.';
            Encoding.ASCII.GetBytes(payloadB64, 0, payloadB64.Length, signingInput, headerB64.Length + 1);
#endif

            // Compute SHA-512 hash of the signing input (ES512 uses SHA-512)
#if NET5_0_OR_GREATER
            return SHA512.HashData(signingInput);
#else
            using (var sha512 = SHA512.Create())
            {
                return sha512.ComputeHash(signingInput);
            }
#endif
        }
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

#if NET5_0_OR_GREATER
    /// <summary>AOT-compatible JSON serialization context for JWKS.</summary>
    [JsonSourceGenerationOptions(
        PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never)]
    [JsonSerializable(typeof(Jwks))]
    [JsonSerializable(typeof(Jwk))]
    [JsonSerializable(typeof(Dictionary<string, object>))]
    [JsonSerializable(typeof(Dictionary<string, JsonElement>))]
    internal partial class SigningJsonContext : JsonSerializerContext
    {
    }
#endif
}
