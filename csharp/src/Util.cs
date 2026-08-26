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

#if NET8_0_OR_GREATER
        /// <summary>
        /// Calculate the exact size needed for a V2 signing payload.
        /// </summary>
        internal static int CalculateV2SigningPayloadSize(
            string method,
            string path,
            ReadOnlySpan<(string, byte[])> headers,
            ReadOnlySpan<byte> body)
        {
            int totalSize = 0;

            // Method (uppercase) + space
            string methodUpper = method.ToUpperInvariant();
            totalSize += Encoding.UTF8.GetByteCount(methodUpper) + SpaceBytes.Length;

            // Path + newline
            totalSize += Encoding.UTF8.GetByteCount(path) + NewlineBytes.Length;

            // Headers: "name: value\n" for each
            for (int i = 0; i < headers.Length; i++)
            {
                var (name, value) = headers[i];
                totalSize += Encoding.UTF8.GetByteCount(name);
                totalSize += ColonSpaceBytes.Length;
                totalSize += value.Length;
                totalSize += NewlineBytes.Length;
            }

            // Body
            totalSize += body.Length;

            return totalSize;
        }

        /// <summary>
        /// Build signing payload directly into a destination span.
        /// Returns the number of bytes written.
        /// The destination span must be large enough (use CalculateV2SigningPayloadSize).
        /// </summary>
        internal static int BuildV2SigningPayloadInto(
            Span<byte> destination,
            string method,
            string path,
            ReadOnlySpan<(string, byte[])> headers,
            ReadOnlySpan<byte> body)
        {
            int position = 0;

            // Write method (uppercase) + space
            string methodUpper = method.ToUpperInvariant();
            position += Encoding.UTF8.GetBytes(methodUpper, destination.Slice(position));
            SpaceBytes.AsSpan().CopyTo(destination.Slice(position));
            position += SpaceBytes.Length;

            // Write path + newline
            position += Encoding.UTF8.GetBytes(path, destination.Slice(position));
            NewlineBytes.AsSpan().CopyTo(destination.Slice(position));
            position += NewlineBytes.Length;

            // Write headers
            for (int i = 0; i < headers.Length; i++)
            {
                var (name, value) = headers[i];
                position += Encoding.UTF8.GetBytes(name, destination.Slice(position));
                ColonSpaceBytes.AsSpan().CopyTo(destination.Slice(position));
                position += ColonSpaceBytes.Length;
                value.AsSpan().CopyTo(destination.Slice(position));
                position += value.Length;
                NewlineBytes.AsSpan().CopyTo(destination.Slice(position));
                position += NewlineBytes.Length;
            }

            // Write body
            body.CopyTo(destination.Slice(position));
            position += body.Length;

            return position;
        }

        /// <summary>
        /// Build signing payload from method, path, some/none/all headers and body.
        /// Optimized for .NET 8+ using span-based operations with pre-calculated size.
        /// Eliminates List allocations and intermediate copies.
        /// </summary>
        internal static byte[] BuildV2SigningPayload(
            string method,
            string path,
            ReadOnlySpan<(string, byte[])> headers,
            ReadOnlySpan<byte> body)
        {
            // Calculate exact size
            int totalSize = CalculateV2SigningPayloadSize(method, path, headers, body);

            // Allocate and write
            byte[] payload = new byte[totalSize];
            BuildV2SigningPayloadInto(payload, method, path, headers, body);

            return payload;
        }
#endif

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
            dict.TryGetValue(key, out var value);
            return value as string;
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
