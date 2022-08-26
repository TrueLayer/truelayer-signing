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
                var jwks = JsonSerializer.Deserialize<Jwks>(jwksJson, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                });
                // ecdsa fully setup later once we know the jwk kid
                var verifier = VerifyWith(ECDsa.Create());
                verifier.jwks = jwks ?? new Jwks();
                return verifier;
            }
            catch (JsonException e)
            {
                throw new SignatureException("invalid jwks", e);
            }
        }

        /// <summary>Start building a `Tl-Signature` header verifier usinga a public key.</summary>
        public static Verifier VerifyWith(ECDsa publicKey) => new Verifier(publicKey);

        /// <summary>Extract kid from unverified jws Tl-Signature.</summary>
        /// <exception cref="SignatureException">Signature is invalid</exception>
        public static string ExtractKid(string tlSignature)
        {
            var kid = Jose.JWT.Headers(tlSignature).GetString("kid");
            if (kid == null)
            {
                throw new SignatureException("missing kid");
            }
            return kid;
        }

        /// <summary>
        /// Extract jku (JSON Web Key URL) from unverified jws Tl-Signature.
        /// Used in webhook signatures providing the public key jwk url.
        /// </summary>
        /// <exception cref="SignatureException">Signature is invalid</exception>
        public static string ExtractJku(string tlSignature)
        {
            var jku = Jose.JWT.Headers(tlSignature).GetString("jku");
            if (jku == null)
            {
                throw new SignatureException("missing jku");
            }
            return jku;
        }

        private ECDsa key;
        // Non-null when verifying using jwks data.
        // This indicates we need to initialize `key` once we have the kid.
        private Jwks? jwks;
        private string method = "";
        private string path = "";
        private Dictionary<string, byte[]> headers = new Dictionary<string, byte[]>(new HeaderNameComparer());
        private HashSet<string> requiredHeaders = new HashSet<string>(new HeaderNameComparer());
        private byte[] body = new byte[0];

        private Verifier(ECDsa publicKey) => key = publicKey;

        /// <summary>Add the request method.</summary>
        public Verifier Method(string method)
        {
            this.method = method;
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
            this.path = path;
            return this;
        }

        /// <summary>
        /// Add a header name and value.
        /// May be called multiple times to add multiple different headers.
        /// </summary>
        public Verifier Header(string name, byte[] value)
        {
            this.headers.Add(name.Trim(), value);
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
            requiredHeaders.Add(name);
            return this;
        }

        /// <summary>Add the full unmodified request body.</summary>
        public Verifier Body(byte[] body)
        {
            this.body = body;
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
            var jwsHeaders = SignatureException.Try(() => Jose.JWT.Headers(tlSignature));

            if (jwks is Jwks jwkeys)
            {
                // initialize public key using jwks data
                var kid = jwsHeaders.GetString("kid") ?? throw new SignatureException("missing kid");
                FindAndImportJwk(jwkeys, kid);
            }

            SignatureException.Ensure(jwsHeaders.GetString("alg") == "ES512", "unsupported jws alg");
            SignatureException.Ensure(jwsHeaders.GetString("tl_version") == "2", "unsupported jws tl_version");
            var signatureParts = tlSignature.Split('.');
            SignatureException.Ensure(signatureParts.Length >= 3, "invalid signature format");

            var signatureHeaderNames = (jwsHeaders.GetString("tl_headers") ?? "")
                .Split(',')
                .Select(h => h.Trim())
                .Where(h => !string.IsNullOrEmpty(h))
                .ToList();

            var signatureHeaderNameSet = new HashSet<string>(signatureHeaderNames, new HeaderNameComparer());
            var missingRequired = requiredHeaders.SingleOrDefault(h => !signatureHeaderNameSet.Contains(h));
            SignatureException.Ensure(missingRequired == null, $"signature is missing required header {missingRequired}");

            var signedHeaders = FilterOrderHeaders(signatureHeaderNames);

            var signingPayload = Util.BuildV2SigningPayload(method, path, signedHeaders, body);
            var jws = $"{signatureParts[0]}.{Base64Url.Encode(signingPayload)}.{signatureParts[2]}";

            SignatureException.Try(() =>
            {
                try
                {
                    return Jose.JWT.Decode(jws, key);
                }
                catch (Jose.IntegrityException)
                {
                    // try again with/without a trailing slash (#80)
                    var path2 = path + "/";
                    if (path.EndsWith("/")) path2 = path.Remove(path.Length - 1);
                    var signingPayload = Util.BuildV2SigningPayload(method, path2, signedHeaders, body);
                    var jws = $"{signatureParts[0]}.{Base64Url.Encode(signingPayload)}.{signatureParts[2]}";
                    return Jose.JWT.Decode(jws, key);
                }
            }, "Invalid signature");
        }

        /// <summary>Find and import jwk into `key`</summary>
        private void FindAndImportJwk(Jwks jwks, string kid)
        {
            var jwk = SignatureException.Try(() => jwks.Keys.First(key => key.Kid == kid), "no jwk found with kid");

            SignatureException.Ensure(jwk.Kty == "EC", "unsupported jwk.kty");
            SignatureException.Ensure(jwk.Crv == "P-521", "unsupported jwk.crv");

            SignatureException.TryAction(() => key.ImportParameters(new ECParameters
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
        private List<(string, byte[])> FilterOrderHeaders(List<string> signedHeaderNames)
        {
            var orderedHeaders = new List<(string, byte[])>(signedHeaderNames.Count);
            foreach (var name in signedHeaderNames)
            {
                if (headers.TryGetValue(name.ToLowerInvariant(), out var value))
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
    }
}
