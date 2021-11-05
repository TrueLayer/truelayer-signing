using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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
            => VerifyWithPem(Encoding.UTF8.GetString(publicKeyPem));

        /// <summary>Start building a `Tl-Signature` header verifier usinga a public key.</summary>
        public static Verifier VerifyWith(ECDsa publicKey) => new Verifier(publicKey);

        /// <summary>Extract kid from unverified jws Tl-Signature.</summary>
        /// <exception cref="SignatureException">Signature is invalid</exception>
        public static string ExtractKid(string tlSignature)
        {
            var kid = Jose.JWT.Headers(tlSignature)["kid"] as string;
            if (kid == null)
            {
                throw new SignatureException("missing kid");
            }
            return kid;
        }

        private ECDsa key;
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
                .Select(e => KeyValuePair.Create(e.Key, e.Value.First())));

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

            SignatureException.Ensure(jwsHeaders.GetString("alg") == "ES512", "unsupported jws alg");
            SignatureException.Ensure(jwsHeaders.GetString("tl_version") == "2", "unsupported jws tl_version");
            SignatureException.Ensure(tlSignature.Contains(".."), "signature must have a detached payload");

            var signatureHeaderNames = (jwsHeaders.GetString("tl_headers") ?? "")
                .Split(",")
                .Select(h => h.Trim())
                .Where(h => !string.IsNullOrEmpty(h))
                .ToList();

            var missingRequired = requiredHeaders.SingleOrDefault(h => !signatureHeaderNames.Contains(h));
            SignatureException.Ensure(missingRequired == null, $"signature is missing required header {missingRequired}");

            var signedHeaders = FilterOrderHeaders(signatureHeaderNames);

            var signingPayload = Util.BuildV2SigningPayload(method, path, signedHeaders, body);
            var jws = tlSignature.Replace("..", $".{Base64Url.Encode(signingPayload)}.");

            SignatureException.Try(() => Jose.JWT.Decode(jws, key), "Invalid signature");
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
