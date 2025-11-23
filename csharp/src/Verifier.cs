using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Primitives;

namespace TrueLayer.Signing
{
    /// <summary>
    /// Builder to verify a request against a `Tl-Signature` header using a public key.
    /// </summary>
    public sealed class Verifier
    {
        /// <summary>
        /// Start building a `Tl-Signature` header verifier using public key RFC 7468 PEM-encoded data.
        /// </summary>
        public static Verifier VerifyWithPem(ReadOnlySpan<char> publicKeyPem)
            => VerifyWith(publicKeyPem.ParsePem());

        /// <summary>
        /// Start building a `Tl-Signature` header verifier using public key RFC 7468 PEM-encoded data.
        /// </summary>
        public static Verifier VerifyWithPem(ReadOnlySpan<byte> publicKeyPem)
#if (NETSTANDARD2_0)
            => VerifyWithPem(Encoding.UTF8.GetString(publicKeyPem.ToArray()).AsSpan());
#else
            => VerifyWithPem(Encoding.UTF8.GetString(publicKeyPem));
#endif

        /// <summary>
        /// Start building a `Tl-Signature` header verifier using public key JWKs JSON response data.
        /// </summary>
        /// <exception cref="SignatureException">Jwks is invalid</exception>
        public static Verifier VerifyWithJwks(string jwksJson) => VerifyWithJwks(jwksJson.ToUtf8());

        /// <summary>
        /// Start building a `Tl-Signature` header verifier using public key JWKs JSON response data.
        /// </summary>
        /// <exception cref="SignatureException">Jwks is invalid</exception>
        public static Verifier VerifyWithJwks(ReadOnlySpan<byte> jwksJson)
        {
            try
            {
#if NET5_0_OR_GREATER
                var jwks = JsonSerializer.Deserialize(jwksJson, SigningJsonContext.Default.Jwks);
#else
                var jwksJsonOptions = new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                var jwks = JsonSerializer.Deserialize<Jwks>(jwksJson, jwksJsonOptions);
#endif
                // ecdsa fully setup later once we know the jwk kid
                var verifier = VerifyWith(ECDsa.Create());
                verifier._jwks = jwks ?? new Jwks();
                return verifier;
            }
            catch (JsonException e)
            {
                throw new SignatureException("invalid jwks", e);
            }
        }

        /// <summary>Start building a `Tl-Signature` header verifier usinga a public key.</summary>
        public static Verifier VerifyWith(ECDsa publicKey) => new Verifier(publicKey);

        /// <summary>Extract a header value from unverified jws Tl-Signature.</summary>
        /// <exception cref="SignatureException">Signature is invalid</exception>
        private static string ExtractJwsHeader(string tlSignature, string headerName)
        {
            var jwsHeaders = ParseJwsHeaders(tlSignature);
            var value = jwsHeaders.GetString(headerName);
            if (value == null)
            {
                throw new SignatureException($"missing {headerName}");
            }
            return value;
        }

        /// <summary>Parse JWS headers from a JWS token in an AOT-compatible way.</summary>
        /// <exception cref="SignatureException">Signature is invalid</exception>
        private static Dictionary<string, object> ParseJwsHeaders(string tlSignature)
        {
            try
            {
                // JWS format: header.payload.signature
                // For detached payload: header..signature
                var firstDot = tlSignature.IndexOf('.');
                if (firstDot <= 0)
                {
                    throw new SignatureException("invalid JWS format");
                }

                var headerB64 = tlSignature.Substring(0, firstDot);
                return ParseJwsHeadersFromB64(headerB64);
            }
            catch (SignatureException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new SignatureException($"Failed to parse JWS: {e.Message}", e);
            }
        }

        /// <summary>Parse JWS headers from base64url-encoded header in an AOT-compatible way.</summary>
        /// <exception cref="SignatureException">Signature is invalid</exception>
        private static Dictionary<string, object> ParseJwsHeadersFromB64(string headerB64)
        {
            try
            {
                var headerJson = Base64Url.Decode(headerB64);

#if NET5_0_OR_GREATER
                var headers = JsonSerializer.Deserialize(headerJson, SigningJsonContext.Default.DictionaryStringObject);
#else
                var headers = JsonSerializer.Deserialize<Dictionary<string, object>>(headerJson);
#endif
                return headers ?? new Dictionary<string, object>();
            }
            catch (SignatureException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new SignatureException($"Failed to parse JWS: {e.Message}", e);
            }
        }

        /// <summary>Extract kid from unverified jws Tl-Signature.</summary>
        /// <exception cref="SignatureException">Signature is invalid</exception>
        public static string ExtractKid(string tlSignature) => ExtractJwsHeader(tlSignature, JwsHeaders.Kid);

        /// <summary>
        /// Extract jku (JSON Web Key URL) from unverified jws Tl-Signature.
        /// Used in webhook signatures providing the public key jwk url.
        /// </summary>
        /// <exception cref="SignatureException">Signature is invalid</exception>
        public static string ExtractJku(string tlSignature) => ExtractJwsHeader(tlSignature, JwsHeaders.Jku);

        private readonly ECDsa _key;
        // Non-null when verifying using jwks data.
        // This indicates we need to initialize `key` once we have the kid.
        private Jwks? _jwks;
        private string _method = "";
        private string _path = "";
        private readonly Dictionary<string, byte[]> _headers = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _requiredHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private byte[] _body = Array.Empty<byte>();

        private Verifier(ECDsa publicKey) => _key = publicKey;

        /// <summary>Add the request method.</summary>
        public Verifier Method(string method)
        {
            this._method = method;
            return this;
        }

        /// <summary>
        /// Add the request absolute path starting with a leading `/` and without any trailing slashes.
        /// </summary>
        public Verifier Path(string path)
        {
            if (!path.StartsWith("/"))
            {
                throw new ArgumentException($"Invalid path \"{path}\" must start with '/'");
            }
            this._path = path;
            return this;
        }

        /// <summary>
        /// Add a header name and value.
        /// May be called multiple times to add multiple different headers.
        /// </summary>
        public Verifier Header(string name, byte[] value)
        {
            this._headers.Add(name.Trim(), value);
            return this;
        }

        /// <summary>
        /// Add a header name and value.
        /// May be called multiple times to add multiple different headers.
        /// </summary>
        public Verifier Header(string name, string value) => Header(name, value.ToUtf8());

        /// <summary>
        /// Appends multiple header names and values.
        /// <br/>
        /// Warning: Only a single value per header name is supported.
        /// </summary>
        public Verifier Headers(IEnumerable<KeyValuePair<string, string>> headers)
        {
            foreach (var entry in headers)
            {
                Header(entry.Key, entry.Value);
            }
            return this;
        }

        /// <summary>
        /// Appends multiple header names and values.
        /// <br/>
        /// Warning: Only a single value per header name is supported.
        /// </summary>
        public Verifier Headers(IEnumerable<KeyValuePair<string, byte[]>> headers)
        {
            foreach (var entry in headers)
            {
                Header(entry.Key, entry.Value);
            }
            return this;
        }

        /// <summary>
        /// Appends multiple header names and values.
        /// <br/>
        /// Warning: Only a single value per header name is supported, the first is used.
        /// </summary>
        public Verifier Headers(IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers)
            => Headers(headers
                .Where(e => e.Value.Any())
                .Select(e => new KeyValuePair<string, string>(e.Key, e.Value.First())));

        /// <summary>
        /// Appends headers from ASP.NET Core IHeaderDictionary without allocation.
        /// <br/>
        /// Warning: Only a single value per header name is supported, the first is used.
        /// </summary>
        public Verifier Headers(IEnumerable<KeyValuePair<string, StringValues>> headers)
        {
            foreach (var header in headers)
            {
                if (header.Value.Count > 0 && header.Value[0] is { } value)
                {
                    Header(header.Key, value);
                }
            }
            return this;
        }

        /// <summary>
        /// Require a header name that must be included in the `Tl-Signature`.
        /// May be called multiple times to add multiple required headers.
        /// </summary>
        public Verifier RequireHeader(string name)
        {
            _requiredHeaders.Add(name);
            return this;
        }

        /// <summary>Add the full unmodified request body.</summary>
        public Verifier Body(byte[] body)
        {
            this._body = body;
            return this;
        }

        /// <summary>
        /// Add the full unmodified request body.
        /// <br/>
        /// In this method it is assumed the body was encoded using, or identical to, UTF-8.
        /// </summary>
        public Verifier Body(string body) => Body(body.ToUtf8());

        /// <summary>Verify the given `Tl-Signature` header value.</summary>
        /// <exception cref="SignatureException">Signature is invalid</exception>
        public void Verify(string tlSignature)
        {
            var dotCount = tlSignature.Count(c => c == '.');
            SignatureException.Ensure(dotCount == 2, "invalid signature format, expected detached JWS (header..signature)");

            // Parse the JWS parts once
            var parts = tlSignature.Split('.');
            var headerB64 = parts[0];
            var signatureB64 = parts[2];

            var jwsHeaders = ParseJwsHeadersFromB64(headerB64);
            if (_jwks is Jwks jwkeys)
            {
                // initialize public key using jwks data
                var kid = jwsHeaders.GetString(JwsHeaders.Kid) ?? throw new SignatureException("missing kid");
                FindAndImportJwk(jwkeys, kid);
            }

            SignatureException.Ensure(jwsHeaders.GetString(JwsHeaders.Alg) == "ES512", "unsupported jws alg");
            var version = jwsHeaders.GetString(JwsHeaders.TlVersion) ?? TryRequireHeaderString("Tl-Signature-Version");
            SignatureException.Ensure(version == "2", "unsupported jws tl_version");

            var tlHeaders = jwsHeaders.GetString(JwsHeaders.TlHeaders) ??
                            TryRequireHeaderString("Tl-Signature-Headers") ?? "";
#if NET8_0_OR_GREATER
            var signatureHeaderNames = tlHeaders
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
#else
            var signatureHeaderNames = tlHeaders
                .Split(',')
                .Select(h => h.Trim())
                .Where(h => !string.IsNullOrEmpty(h))
                .ToArray();
#endif

            var missingRequired = _requiredHeaders.Except(signatureHeaderNames, StringComparer.OrdinalIgnoreCase);
            if (missingRequired.Any())
            {
                throw new SignatureException($"signature is missing required headers {string.Join(",", missingRequired)}");
            }

            var signedHeaders = FilterOrderHeaders(signatureHeaderNames);

            var signingPayload = Util.BuildV2SigningPayload(_method, _path, signedHeaders, _body);

            SignatureException.Try(() =>
            {
                try
                {
                    VerifyJwsSignature(headerB64, signatureB64, signingPayload, _key);
                    return true;
                }
                catch (SignatureException)
                {
                    // try again with/without a trailing slash (#80)
                    var path2 = _path.EndsWith("/")
                        ? _path.Substring(0, _path.Length - 1)
                        : _path + "/";
                    var alternatePayload = Util.BuildV2SigningPayload(_method, path2, signedHeaders, _body);
                    VerifyJwsSignature(headerB64, signatureB64, alternatePayload, _key);
                    return true;
                }
            }, "Invalid signature");
        }

        /// <summary>Verify JWS signature manually without using reflection-based deserialization (AOT-compatible).</summary>
        /// <exception cref="SignatureException">Signature is invalid</exception>
        private static void VerifyJwsSignature(string headerB64, string signatureB64, byte[] payload, ECDsa key)
        {
            try
            {
                // Decode the signature - ES512 signatures are IEEE P1363 format (raw r||s)
                var signature = Base64Url.Decode(signatureB64);

                // Build the signing input: base64url(header).base64url(payload)
                // For detached signatures, we reconstruct using the provided payload
                var payloadB64 = Base64Url.Encode(payload);
                var signingInput = Encoding.UTF8.GetBytes($"{headerB64}.{payloadB64}");

                // Compute SHA-512 hash of the signing input (ES512 uses SHA-512)
#if NET5_0_OR_GREATER
                var hash = SHA512.HashData(signingInput);
#else
                byte[] hash;
                using (var sha512 = SHA512.Create())
                {
                    hash = sha512.ComputeHash(signingInput);
                }
#endif

                // Verify the signature using ECDSA
                // The signature is in IEEE P1363 format (concatenated r||s), which is what VerifyHash expects
                if (!key.VerifyHash(hash, signature))
                {
                    throw new SignatureException("signature verification failed");
                }
            }
            catch (SignatureException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new SignatureException($"signature verification failed: {e.Message}", e);
            }
        }

        /// <summary>Find and import jwk into `key`</summary>
        private void FindAndImportJwk(Jwks jwks, string kid)
        {
            var jwk = SignatureException.Try(() => jwks.Keys.First(key => key.Kid == kid), "no jwk found with kid");

            SignatureException.Ensure(jwk.Kty == "EC", "unsupported jwk.kty");
            SignatureException.Ensure(jwk.Crv == "P-521", "unsupported jwk.crv");

            SignatureException.TryAction(() => _key.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP521,
                Q = new ECPoint
                {
                    // Note: A CryptographicException will be thrown if the coord byte
                    // representations have uneven length, so must be zero padded to 66
                    X = Base64Url.Decode(jwk.X).PrependZeroPad(66),
                    Y = Base64Url.Decode(jwk.Y).PrependZeroPad(66),
                }
            }), "invalid jwk data");
        }

        /// <summary>Filter and order headers to match jws header `tl_headers`.</summary>
        private List<(string, byte[])> FilterOrderHeaders(string[] signedHeaderNames)
        {
            var orderedHeaders = new List<(string, byte[])>(signedHeaderNames.Length);
            foreach (var name in signedHeaderNames)
            {
                if (_headers.TryGetValue(name, out var value))
                {
                    orderedHeaders.Add((name, value));
                }
                else
                {
                    throw new SignatureException($"Missing tl_header `{name}` declared in signature");
                }
            }
            return orderedHeaders;
        }

        private string? TryRequireHeaderString(string name)
        {
            if (GetHeaderString(name) is {} value)
            {
                _requiredHeaders.Add(name);
                return value;
            }

            return null;
        }

        private string? GetHeaderString(string key) =>
            _headers.TryGetValue(key, out var value)
                ? Encoding.UTF8.GetString(value)
                : null;
    }
}
