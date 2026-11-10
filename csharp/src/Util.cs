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
        private static readonly byte[] DotBytes = Encoding.UTF8.GetBytes(".");

        /// <summary>
        /// Build signing payload from method, path, some/none/all headers and body.
        /// </summary>
        internal static byte[] BuildV2SigningPayload(
            string method,
            string path,
            IEnumerable<(string, byte[])> headers,
            byte[] body)
        {
            var methodBytes = method.ToUpperInvariant().ToUtf8();
            var pathBytes = path.ToUtf8();
            var headerList = new List<(byte[] Name, byte[] Value)>();
            var size = methodBytes.Length + SpaceBytes.Length + pathBytes.Length + NewlineBytes.Length + body.Length;
            foreach (var (name, value) in headers)
            {
                var nameBytes = name.ToUtf8();
                headerList.Add((nameBytes, value));
                size += nameBytes.Length + ColonSpaceBytes.Length + value.Length + NewlineBytes.Length;
            }

            // Exact-size buffer: no List<byte> growth and no ToArray copy
            var payload = new byte[size];
            var offset = 0;
            Append(payload, ref offset, methodBytes);
            Append(payload, ref offset, SpaceBytes);
            Append(payload, ref offset, pathBytes);
            Append(payload, ref offset, NewlineBytes);
            foreach (var (nameBytes, value) in headerList)
            {
                Append(payload, ref offset, nameBytes);
                Append(payload, ref offset, ColonSpaceBytes);
                Append(payload, ref offset, value);
                Append(payload, ref offset, NewlineBytes);
            }

            Append(payload, ref offset, body);
            return payload;
        }

        private static void Append(byte[] destination, ref int offset, byte[] source)
        {
            Buffer.BlockCopy(source, 0, destination, offset, source.Length);
            offset += source.Length;
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

        /// <summary>
        /// Computes the SHA-512 hash of the JWS signing input "base64url(header).base64url(payload)"
        /// from the raw payload bytes. On .NET 9+ the payload is encoded into a pooled buffer and hashed
        /// without creating an intermediate base64url string.
        /// </summary>
        internal static byte[] ComputeJwsSigningHash(string headerB64, byte[] payload)
        {
#if NET9_0_OR_GREATER
            var encodedLength = System.Buffers.Text.Base64Url.GetEncodedLength(payload.Length);
            var buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(encodedLength);
            try
            {
                System.Buffers.Text.Base64Url.EncodeToUtf8(payload, buffer, out _, out var written);
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
                hash.AppendData(Encoding.ASCII.GetBytes(headerB64));
                hash.AppendData(DotBytes);
                hash.AppendData(buffer, 0, written);
                return hash.GetHashAndReset();
            }
            finally
            {
                System.Buffers.ArrayPool<byte>.Shared.Return(buffer);
            }
#else
            return ComputeJwsSigningHash(headerB64, Base64Url.Encode(payload));
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
