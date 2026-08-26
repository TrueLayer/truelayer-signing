#if NET8_0_OR_GREATER
using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Jose;

namespace TrueLayer.Signing
{
    /// <summary>
    /// High-performance span-based verification API for .NET 8+.
    /// Optimized for zero-allocation scenarios when body is available as ReadOnlySpan&lt;byte&gt;.
    /// </summary>
    public static class VerifierSpan
    {
        /// <summary>
        /// Verify a request signature using public key RFC 7468 PEM-encoded data.
        /// This method is optimized for high-throughput scenarios and minimizes allocations.
        /// </summary>
        /// <param name="publicKeyPem">RFC 7468 PEM-encoded public key data</param>
        /// <param name="method">HTTP request method (e.g., "POST")</param>
        /// <param name="path">Request absolute path starting with a leading '/' and without any trailing slashes</param>
        /// <param name="headers">Request headers to include in signature verification</param>
        /// <param name="body">Full unmodified request body</param>
        /// <param name="tlSignature">The Tl-Signature header value to verify</param>
        /// <param name="requiredHeaders">Optional set of header names that must be included in the signature</param>
        /// <exception cref="SignatureException">Signature is invalid or verification failed</exception>
        /// <exception cref="ArgumentException">Invalid path format</exception>
        public static void VerifyWithPem(
            ReadOnlySpan<byte> publicKeyPem,
            string method,
            string path,
            IEnumerable<KeyValuePair<string, byte[]>> headers,
            ReadOnlySpan<byte> body,
            string tlSignature,
            IEnumerable<string>? requiredHeaders = null)
        {
            ValidatePath(path);

            // Parse PEM and create ECDsa key
            // Optimization: decode UTF8 to stack-allocated char buffer (saves ~2KB allocation)
            Span<char> pemChars = publicKeyPem.Length <= 4096
                ? stackalloc char[publicKeyPem.Length]
                : new char[publicKeyPem.Length];

            var charCount = Encoding.UTF8.GetChars(publicKeyPem, pemChars);
            ReadOnlySpan<char> pemSpan = pemChars.Slice(0, charCount);
            using var publicKey = pemSpan.ParsePem();

            // Perform verification
            VerifyCore(publicKey, method, path, headers, body, tlSignature, requiredHeaders);
        }

        /// <summary>
        /// Verify a request signature using a pre-parsed public key.
        /// Use this when the same key is used for multiple verifications to avoid repeated PEM parsing.
        /// This is the most optimized verification path.
        /// </summary>
        /// <param name="publicKey">Pre-parsed ECDsa public key</param>
        /// <param name="method">HTTP request method (e.g., "POST")</param>
        /// <param name="path">Request absolute path starting with a leading '/' and without any trailing slashes</param>
        /// <param name="headers">Request headers to include in signature verification</param>
        /// <param name="body">Full unmodified request body</param>
        /// <param name="tlSignature">The Tl-Signature header value to verify</param>
        /// <param name="requiredHeaders">Optional set of header names that must be included in the signature</param>
        /// <exception cref="SignatureException">Signature is invalid or verification failed</exception>
        /// <exception cref="ArgumentException">Invalid path format</exception>
        public static void VerifyWith(
            ECDsa publicKey,
            string method,
            string path,
            IEnumerable<KeyValuePair<string, byte[]>> headers,
            ReadOnlySpan<byte> body,
            string tlSignature,
            IEnumerable<string>? requiredHeaders = null)
        {
            ValidatePath(path);
            VerifyCore(publicKey, method, path, headers, body, tlSignature, requiredHeaders);
        }

        /// <summary>
        /// Validate that path starts with '/' as required by the signature specification.
        /// </summary>
        private static void ValidatePath(string path)
        {
            if (!path.StartsWith("/"))
            {
                throw new ArgumentException($"Invalid path \"{path}\" must start with '/'");
            }
        }

        /// <summary>
        /// Core verification logic shared by all VerifierSpan methods.
        /// Optimized to use direct ECDsa.VerifyData, bypassing Jose.JWT overhead.
        /// </summary>
        private static void VerifyCore(
            ECDsa publicKey,
            string method,
            string path,
            IEnumerable<KeyValuePair<string, byte[]>> headers,
            ReadOnlySpan<byte> body,
            string tlSignature,
            IEnumerable<string>? requiredHeaders)
        {
            // Parse JWS format: base64url(header)..base64url(signature)
            var parts = tlSignature.Split('.');
            SignatureException.Ensure(parts.Length == 3, "invalid signature format, expected detached JWS (header..signature)");
            SignatureException.Ensure(string.IsNullOrEmpty(parts[1]), "expected detached JWS with empty payload");

            // Decode JWS header using System.Text.Json (faster than Jose.JWT.Headers)
            var headerBytes = Jose.Base64Url.Decode(parts[0]);
            var jwsHeaders = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(headerBytes)
                ?? throw new SignatureException("invalid JWS header");

            // Validate algorithm and version
            var alg = jwsHeaders.TryGetValue("alg", out var algElem) ? algElem.GetString() : null;
            SignatureException.Ensure(alg == "ES512", "unsupported jws alg");

            var version = jwsHeaders.TryGetValue("tl_version", out var verElem) ? verElem.GetString() : null;
            if (version == null)
            {
                version = GetHeaderString(headers, "Tl-Signature-Version");
            }
            SignatureException.Ensure(version == "2", "unsupported jws tl_version");

            // Get signed header names
            var tlHeaders = jwsHeaders.TryGetValue("tl_headers", out var headersElem) ? headersElem.GetString() : null;
            if (tlHeaders == null)
            {
                tlHeaders = GetHeaderString(headers, "Tl-Signature-Headers") ?? "";
            }

            var signatureHeaderNames = tlHeaders
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            // Validate required headers
            if (requiredHeaders != null)
            {
                var requiredSet = new HashSet<string>(requiredHeaders, StringComparer.OrdinalIgnoreCase);
                var missingRequired = requiredSet.Except(signatureHeaderNames, StringComparer.OrdinalIgnoreCase);
                if (missingRequired.Any())
                {
                    throw new SignatureException($"signature is missing required headers {string.Join(",", missingRequired)}");
                }
            }

            // Filter and order headers
            var signedHeaders = FilterOrderHeaders(headers, signatureHeaderNames);

            // Decode signature (IEEE P1363 format: r||s, each 66 bytes for P-521)
            var signature = Jose.Base64Url.Decode(parts[2]);

            // Pre-encode JWS header to UTF8 bytes (reused for both attempts if needed)
            int headerUtf8Length = Encoding.UTF8.GetByteCount(parts[0]);
            Span<byte> headerUtf8Bytes = headerUtf8Length <= 512
                ? stackalloc byte[headerUtf8Length]
                : new byte[headerUtf8Length];
            Encoding.UTF8.GetBytes(parts[0], headerUtf8Bytes);

            // Try verification with original path
            if (TryVerifyWithPath(publicKey, method, path, signedHeaders, body, headerUtf8Bytes, signature))
            {
                return;
            }

            // Try with alternate path (trailing slash handling)
            var alternatePath = path.EndsWith("/")
                ? path.Substring(0, path.Length - 1)
                : path + "/";

            if (TryVerifyWithPath(publicKey, method, alternatePath, signedHeaders, body, headerUtf8Bytes, signature))
            {
                return;
            }

            throw new SignatureException("Invalid signature");
        }

        /// <summary>
        /// Attempt to verify signature with a specific path.
        /// Returns true if verification succeeds, false otherwise.
        /// </summary>
        private static bool TryVerifyWithPath(
            ECDsa publicKey,
            string method,
            string path,
            ReadOnlySpan<(string, byte[])> signedHeaders,
            ReadOnlySpan<byte> body,
            ReadOnlySpan<byte> headerUtf8Bytes,
            byte[] signature)
        {
            // Calculate signing payload size
            var payloadSize = Util.CalculateV2SigningPayloadSize(method, path, signedHeaders, body);

            // Optimize: stackalloc for typical payloads (<2KB), heap allocate for larger
            Span<byte> payloadBuffer = payloadSize <= 2048
                ? stackalloc byte[payloadSize]
                : new byte[payloadSize];

            // Build signing payload directly into buffer (zero-copy)
            Util.BuildV2SigningPayloadInto(payloadBuffer, method, path, signedHeaders, body);

            // Construct JWS signing string efficiently: base64url(header) + "." + base64url(payload)
            int payloadBase64UrlLength = GetBase64UrlLength(payloadSize);
            int signingStringLength = headerUtf8Bytes.Length + 1 + payloadBase64UrlLength;

            // Allocate buffer for signing string (stackalloc for typical sizes)
            Span<byte> signingStringBuffer = signingStringLength <= 4096
                ? stackalloc byte[signingStringLength]
                : new byte[signingStringLength];

            // Build signing string: header_bytes + '.' + base64url(payload)
            int position = 0;
            headerUtf8Bytes.CopyTo(signingStringBuffer);
            position += headerUtf8Bytes.Length;
            signingStringBuffer[position++] = (byte)'.'; // ASCII '.'

            // Base64url encode payload directly into buffer (span-based, zero-copy)
            var payloadBase64Span = signingStringBuffer.Slice(position);
            EncodeBase64Url(payloadBuffer, payloadBase64Span);

            // Verify signature
            try
            {
                return publicKey.VerifyData(signingStringBuffer, signature, HashAlgorithmName.SHA512);
            }
            catch (CryptographicException)
            {
                // Cryptographic exceptions during verification are expected for invalid signatures
                return false;
            }
        }

        /// <summary>
        /// Filter and order headers to match jws header `tl_headers`.
        /// Optimized: uses array instead of List to reduce allocations.
        /// </summary>
        private static (string, byte[])[] FilterOrderHeaders(
            IEnumerable<KeyValuePair<string, byte[]>> headers,
            string[] signedHeaderNames)
        {
            var orderedHeaders = new (string, byte[])[signedHeaderNames.Length];
            int writeIndex = 0;

            foreach (var name in signedHeaderNames)
            {
                bool found = false;
                foreach (var header in headers)
                {
                    if (header.Key.AsSpan().Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
                    {
                        orderedHeaders[writeIndex++] = (name, header.Value);
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    throw new SignatureException($"Missing tl_header `{name}` declared in signature");
                }
            }

            return orderedHeaders;
        }

        /// <summary>
        /// Get a header value as a string, or null if not found.
        /// </summary>
        private static string? GetHeaderString(IEnumerable<KeyValuePair<string, byte[]>> headers, string key)
        {
            foreach (var header in headers)
            {
                if (string.Equals(header.Key, key, StringComparison.OrdinalIgnoreCase))
                {
                    return Encoding.UTF8.GetString(header.Value);
                }
            }
            return null;
        }

        /// <summary>
        /// Calculate the exact length of base64url encoding for a given byte count.
        /// Base64url removes padding, so it's shorter than standard base64.
        /// </summary>
        private static int GetBase64UrlLength(int byteCount)
        {
            // Standard base64 length with padding
            int base64Length = ((byteCount + 2) / 3) * 4;
            // Base64url removes trailing '=' padding
            int paddingLength = (3 - (byteCount % 3)) % 3;
            return base64Length - paddingLength;
        }

        /// <summary>
        /// Efficiently encode bytes to base64url format directly into a span.
        /// Uses .NET 9's System.Buffers.Text.Base64Url for optimal performance, or Jose.Base64Url for earlier versions.
        /// </summary>
        private static void EncodeBase64Url(ReadOnlySpan<byte> source, Span<byte> destination)
        {
#if NET9_0_OR_GREATER
            System.Buffers.Text.Base64Url.EncodeToUtf8(source, destination, out _, out _);
#else
            // For .NET 8, use Jose.Base64Url which still avoids some allocations
            var encoded = Jose.Base64Url.Encode(source.ToArray());
            Encoding.UTF8.GetBytes(encoded, destination);
#endif
        }
    }
}
#endif
