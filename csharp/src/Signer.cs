using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Jose;

namespace TrueLayer.Signing
{
    /// <summary>
    /// Builder to generate a Tl-Signature header value using a private key.
    /// </summary>
    public sealed class Signer
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
        public static Signer SignWith(string kid, ECDsa privateKey) => new Signer(kid, privateKey);

        private ECDsa key;
        private string kid;
        private string method = "POST";
        private string path = "";
        private Dictionary<string, byte[]> headers = new Dictionary<string, byte[]>(new HeaderNameComparer());
        private byte[] body = new byte[0];

        private Signer(string _kid, ECDsa privateKey)
        {
            key = privateKey;
            kid = _kid;
        }

        /// <summary>Add the request method, defaults to `"POST"` if unspecified.</summary>
        public Signer Method(string method)
        {
            this.method = method;
            return this;
        }

        /// <summary>
        /// Add the request absolute path starting with a leading `/` and without any trailing slashes.
        /// </summary>
        public Signer Path(string path)
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
        /// <br/>
        /// Warning: Only a single value per header name is supported.
        /// </summary>
        public Signer Header(string name, byte[] value)
        {
            this.headers.Add(name.Trim(), value);
            return this;
        }

        /// <summary>
        /// Add a header name and value.
        /// May be called multiple times to add multiple different headers.
        /// <br/>
        /// Warning: Only a single value per header name is supported.
        /// </summary>
        public Signer Header(string name, string value) => Header(name, value.ToUtf8());

        /// <summary>
        /// Appends multiple header names and values.
        /// <br/>
        /// Warning: Only a single value per header name is supported.
        /// </summary>
        public Signer Headers(IEnumerable<KeyValuePair<string, string>> headers)
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
        public Signer Headers(IEnumerable<KeyValuePair<string, byte[]>> headers)
        {
            foreach (var entry in headers)
            {
                Header(entry.Key, entry.Value);
            }
            return this;
        }

        /// <summary>
        /// Add the full request body.
        /// Note: This *must* be identical to what is sent with the request.
        /// </summary>
        public Signer Body(byte[] body)
        {
            this.body = body;
            return this;
        }

        /// <summary>
        /// Add the full request body.
        /// Note: This *must* be identical to what is sent with the request.
        /// <br/>
        /// In this method it is assumed the body will be encoded using UTF-8.
        /// </summary>
        public Signer Body(string body) => Body(body.ToUtf8());

        /// <summary>Produce a JWS `Tl-Signature` v2 header value.</summary>
        public string Sign()
        {
            var headerList = headers.Select(e => (e.Key, e.Value)).ToList();
            var jwsHeaders = new Dictionary<string, object>()
            {
                {"alg", "ES512"},
                {"kid", kid},
                {"tl_version", "2"},
                {"tl_headers", string.Join(",", headerList.Select(h => h.Key))},
            };
            var signingPayload = Util.BuildV2SigningPayload(method, path, headerList, body);

            return JWT.EncodeBytes(
                signingPayload,
                key,
                JwsAlgorithm.ES512,
                jwsHeaders,
                options: new JwtOptions { DetachPayload = true });
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="headers"></param>
        /// <param name="kid"></param>
        /// <param name="key"></param>
        /// <param name="httpMethod"></param>
        /// <param name="path"></param>
        /// <param name="body"></param>
        /// <returns></returns>
        public static string Sign(
            Dictionary<string, string> headers,
            string kid,
            ReadOnlySpan<char> key,
            HttpMethod httpMethod,
            string path,
            string body)
        {
            var headerList = headers.Select(e => (e.Key, e.Value.ToUtf8())).ToList();
            var jwsHeaders = new Dictionary<string, object>()
            {
                {"alg", "ES512"},
                {"kid", kid},
                {"tl_version", "2"},
                {"tl_headers", string.Join(",", headerList.Select(h => h.Key))},
            };
            var signingPayload = Util.BuildV2SigningPayload(httpMethod.Method, path, headerList, body.ToUtf8());

            return JWT.EncodeBytes(
                signingPayload,
                key.ParsePem(),
                JwsAlgorithm.ES512,
                jwsHeaders,
                options: new JwtOptions { DetachPayload = true });
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="headers"></param>
        /// <param name="kid"></param>
        /// <param name="key"></param>
        /// <param name="httpMethod"></param>
        /// <param name="path"></param>
        /// <param name="body"></param>
        /// <returns></returns>
        public static string SignSb(
            Dictionary<string, string> headers,
            string kid,
            ReadOnlySpan<char> key,
            HttpMethod httpMethod,
            string path,
            string body)
        {
            var jwsHeaders = new Dictionary<string, object>()
            {
                {"alg", "ES512"},
                {"kid", kid},
                {"tl_version", "2"},
                {"tl_headers", string.Join(",", headers.Select(h => h.Key))},
            };

            var sb = new StringBuilder().AppendFormat("{0} {1}\n", httpMethod.Method, path);
            foreach (var kv in headers)
            {
                sb.AppendFormat("{0}: {1}\n", kv.Key, kv.Value);
            }
            sb.Append(body);

            return JWT.Encode(
                sb.ToString(),
                key.ParsePem(),
                JwsAlgorithm.ES512,
                jwsHeaders,
                options: new JwtOptions { DetachPayload = true });
        }
    }
}
