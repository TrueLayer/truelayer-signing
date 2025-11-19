namespace TrueLayer.Signing
{
    /// <summary>
    /// Constants for JWS (JSON Web Signature) header parameter names.
    /// </summary>
    internal static class JwsHeaders
    {
        /// <summary>Key ID - identifies the key used to sign the JWS.</summary>
        public const string Kid = "kid";

        /// <summary>JWK Set URL - URL that refers to a resource for a set of JSON-encoded public keys.</summary>
        public const string Jku = "jku";

        /// <summary>Algorithm - cryptographic algorithm used to secure the JWS.</summary>
        public const string Alg = "alg";

        /// <summary>TrueLayer signature version.</summary>
        public const string TlVersion = "tl_version";

        /// <summary>TrueLayer headers included in the signature.</summary>
        public const string TlHeaders = "tl_headers";
    }
}
