using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Jose;

namespace TrueLayer.Signing
{
    /// <summary>
    /// Builder to verify a request against a `Tl-Signature` header using a public key.
    /// </summary>
    public sealed class Verifier
    {
        private static readonly JsonSerializerOptions JwksJsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        
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
                var jwks = JsonSerializer.Deserialize<Jwks>(jwksJson, JwksJsonOptions);
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
            IDictionary<string, object>? jwsHeaders;
            try
            {
                jwsHeaders = Jose.JWT.Headers(tlSignature);
            }
            catch (Exception e)
            {
                throw new SignatureException($"Failed to parse JWS: {e.Message}", e);
            }
            var value = jwsHeaders.GetString(headerName);
            if (value == null)
            {
                throw new SignatureException($"missing {headerName}");
            }
            return value;
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

            IDictionary<string, object>? jwsHeaders;
            try
            {
                jwsHeaders = Jose.JWT.Headers(tlSignature);
            }
            catch (Exception e)
            {
                throw new SignatureException($"Failed to parse JWS: {e.Message}", e);
            }
            if (_jwks is Jwks jwkeys)
            {
                // initialize public key using jwks data
                var kid = jwsHeaders.GetString(JwsHeaders.Kid) ?? throw new SignatureException("missing kid");
                FindAndImportJwk(jwkeys, kid);
            }

            SignatureException.Ensure(jwsHeaders.GetString(JwsHeaders.Alg) == "ES512", "unsupported jws alg");
            var version = jwsHeaders.GetString(JwsHeaders.TlVersion) ?? TryRequireHeaderString("Tl-Signature-Version");
            SignatureException.Ensure(version == "2", "unsupported jws tl_version");

#if NET8_0_OR_GREATER
            var signatureHeaderNames = (jwsHeaders.GetString(JwsHeaders.TlHeaders) ?? TryRequireHeaderString("Tl-Signature-Headers") ?? "")
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
#else
            var signatureHeaderNames = (jwsHeaders.GetString(JwsHeaders.TlHeaders) ?? TryRequireHeaderString("Tl-Signature-Headers") ?? "")
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
                    return Jose.JWT.DecodeBytes(tlSignature, _key, payload: signingPayload);
                }
                catch (Jose.IntegrityException)
                {
                    // try again with/without a trailing slash (#80)
                    var path2 = _path.EndsWith("/")
                        ? _path.Substring(0, _path.Length - 1)
                        : _path + "/";
                    var alternatePayload = Util.BuildV2SigningPayload(_method, path2, signedHeaders, _body);
                    return Jose.JWT.DecodeBytes(tlSignature, _key, payload: alternatePayload);
                }
            }, "Invalid signature");
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
