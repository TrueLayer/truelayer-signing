using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Jose;

namespace TrueLayer.Signing
{
    /// <summary>
    /// Builder to generate a Tl-Signature header value.
    /// </summary>
    public abstract class Signer : Signer<Signer>
    {
        /// <summary>
        /// Start building a request Tl-Signature header value using private key
        /// RFC 7468 PEM-encoded data and the key's kid.
        /// </summary>
        public static Signer SignWithPem(string kid, ReadOnlySpan<char> privateKeyPem)
            => SignWith(kid, privateKeyPem.ParsePem());

        /// <summary>
        /// Start building a request Tl-Signature header value using private key
        /// RFC 7468 PEM-encoded data and the key's kid.
        /// </summary>
        public static Signer SignWithPem(string kid, ReadOnlySpan<byte> privateKeyPem)
#if (NETSTANDARD2_0)
            => SignWithPem(kid, Encoding.UTF8.GetString(privateKeyPem.ToArray()).AsSpan());
#else
            => SignWithPem(kid, Encoding.UTF8.GetString(privateKeyPem));
#endif

        /// <summary>
        /// Start building a request Tl-Signature header value using private key and the key's kid.
        /// </summary>
        public static Signer SignWith(string kid, ECDsa privateKey) => new PrivateKeySigner(kid, privateKey);

        /// <summary>
        /// Start building a request Tl-Signature header value using the key ID of the signing key (kid)
        /// and a function that accepts the payload to sign and returns the signature in IEEE P1363 format. 
        /// </summary>
        public static AsyncSigner SignWithFunction(string kid, Func<string, Task<string>> signAsync) => new FunctionSigner(kid, signAsync);
        
        protected internal Signer(string kid) : base(kid)
        {
        }

        /// <summary>Produce a JWS `Tl-Signature` v2 header value.</summary>
        public abstract string Sign();
    }

    public abstract class Signer<TSigner> where TSigner : Signer<TSigner>
    {
        private readonly string _kid;
        private readonly TSigner _this;
        protected internal string _method = "POST";
        protected internal string _path = "";
        protected internal readonly Dictionary<string, byte[]> _headers = new(new HeaderNameComparer());
        protected internal byte[] _body = Array.Empty<byte>();
        protected internal string? _jku;

        protected internal Signer(string kid)
        {
            _kid = kid;
            _this = (TSigner) this;
        }

        /// <summary>Add the request method, defaults to `"POST"` if unspecified.</summary>
        public TSigner Method(string method)
        {
            _method = method;
            return _this;
        }

        /// <summary>
        /// Add the request absolute path starting with a leading `/` and without any trailing slashes.
        /// </summary>
        public TSigner Path(string path)
        {
            if (!path.StartsWith("/"))
            {
                throw new ArgumentException($"Invalid path \"{path}\" must start with '/'");
            }

            _path = path;
            return _this;
        }

        /// <summary>
        /// Add a header name and value.
        /// May be called multiple times to add multiple different headers.
        /// <br/>
        /// Warning: Only a single value per header name is supported.
        /// </summary>
        public TSigner Header(string name, byte[] value)
        {
            _headers.Add(name.Trim(), value);
            return _this;
        }

        /// <summary>
        /// Add a header name and value.
        /// May be called multiple times to add multiple different headers.
        /// <br/>
        /// Warning: Only a single value per header name is supported.
        /// </summary>
        public TSigner Header(string name, string value) => Header(name, value.ToUtf8());

        /// <summary>
        /// Appends multiple header names and values.
        /// <br/>
        /// Warning: Only a single value per header name is supported.
        /// </summary>
        public TSigner Headers(IEnumerable<KeyValuePair<string, string>> headers)
        {
            foreach (var entry in headers)
            {
                Header(entry.Key, entry.Value);
            }

            return _this;
        }

        /// <summary>
        /// Appends multiple header names and values.
        /// <br/>
        /// Warning: Only a single value per header name is supported.
        /// </summary>
        public TSigner Headers(IEnumerable<KeyValuePair<string, byte[]>> headers)
        {
            foreach (var entry in headers)
            {
                Header(entry.Key, entry.Value);
            }

            return _this;
        }

        /// <summary>
        /// Add the full request body.
        /// Note: This *must* be identical to what is sent with the request.
        /// </summary>
        public TSigner Body(byte[] body)
        {
            _body = body;
            return _this;
        }

        /// <summary>
        /// Add the full request body.
        /// Note: This *must* be identical to what is sent with the request.
        /// <br/>
        /// In this method it is assumed the body will be encoded using UTF-8.
        /// </summary>
        public TSigner Body(string body) => Body(body.ToUtf8());
        
        /// <summary>
        /// Sets the jku (JSON Web Key Set URL) in the JWS headers of the signature. 
        /// </summary>
        public TSigner Jku(string jku)
        {
            _jku = jku;
            return _this;
        }

        protected internal Dictionary<string, object> CreateJwsHeaders()
        {
            var jwsHeaders = new Dictionary<string, object>
            {
                {"alg", "ES512"},
                {"kid", _kid},
                {"tl_version", "2"},
                {"tl_headers", string.Join(",", _headers.Select(h => h.Key))},
            };

            if (_jku is not null)
            {
                jwsHeaders.Add("jku", _jku);
            }

            return jwsHeaders;
        }
    }
    
    /// <summary>
    /// Builder to generate a Tl-Signature header value.
    /// </summary>
    public abstract class AsyncSigner : Signer<AsyncSigner>
    {
        protected internal AsyncSigner(string kid) : base(kid)
        {
        }

        /// <summary>Produce a JWS `Tl-Signature` v2 header value.</summary>
        public abstract Task<string> SignAsync();
    }

    internal sealed class PrivateKeySigner : Signer
    {
        private readonly ECDsa _key;

        internal PrivateKeySigner(string kid, ECDsa privateKey) : base(kid)
        {
            _key = privateKey;
        }
        
        public override string Sign()
        {
            var jwsHeaders = CreateJwsHeaders();
            var headerList = _headers.Select(e => (e.Key, e.Value));
            var signingPayload = Util.BuildV2SigningPayload(_method, _path, headerList, _body);

            return JWT.EncodeBytes(
                signingPayload,
                _key,
                JwsAlgorithm.ES512,
                jwsHeaders,
                options: new JwtOptions {DetachPayload = true});
        }
    }
    
    internal sealed class FunctionSigner : AsyncSigner
    {
        private readonly Func<string, Task<string>> _signAsync;
        
        internal FunctionSigner(string kid, Func<string, Task<string>> signAsync) : base(kid)
        {
            _signAsync = signAsync;
        }
        
        public override async Task<string> SignAsync()
        {
            var jwsHeaders = CreateJwsHeaders();
            var serializedJwsHeaders = JsonSerializer.SerializeToUtf8Bytes(jwsHeaders);
            var serializedJwsHeadersB64 = Base64Url.Encode(serializedJwsHeaders);

            var headerList = _headers.Select(e => (e.Key, e.Value));
            var signingPayload = Util.BuildV2SigningPayload(_method, _path, headerList, _body);
            var signingPayloadB64 = Base64Url.Encode(signingPayload);

            var signingMessage = $"{serializedJwsHeadersB64}.{signingPayloadB64}";

            var signature = await _signAsync(signingMessage);

            return $"{serializedJwsHeadersB64}..{signature}";
        }
    }
}