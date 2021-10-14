use crate::{
    base64::{DecodeUrlSafeBase64, ToUrlSafeBase64},
    http::HeaderName,
    jws::JwsHeader,
    openssl,
    sign::build_v2_signing_payload,
    Error,
};
use anyhow::anyhow;
use indexmap::{IndexMap, IndexSet};
use std::fmt;

/// Builder to verify a request against a `Tl-Signature` header.
pub struct Verifier<'a> {
    public_key: &'a [u8],
    body: &'a [u8],
    method: &'a str,
    path: &'a str,
    headers: IndexMap<HeaderName<'a>, &'a [u8]>,
    required_headers: IndexSet<HeaderName<'a>>,
    allow_v1: bool,
}

/// Debug does not display key info.
impl fmt::Debug for Verifier<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Verifier")
    }
}

impl<'a> Verifier<'a> {
    pub(crate) fn new(public_key: &'a [u8]) -> Self {
        Self {
            public_key,
            body: &[],
            method: "",
            path: "",
            headers: <_>::default(),
            required_headers: <_>::default(),
            allow_v1: false,
        }
    }

    /// Add the full received request body.
    pub fn body(mut self, body: &'a [u8]) -> Self {
        self.body = body;
        self
    }

    /// Add the request method, e.g. `"POST"`.
    pub fn method(mut self, method: &'a str) -> Self {
        self.method = method;
        self
    }

    /// Add the request path, e.g. `"/payouts"`.
    pub fn path(mut self, path: &'a str) -> Self {
        self.path = path;
        self
    }

    /// Add a header name & value.
    /// May be called multiple times to add multiple different headers.
    ///
    /// All request headers may be added here, any headers not mentioned
    /// in the jws signature header will be ignored unless required using
    /// [`Verifier::require_header`].
    pub fn header(mut self, key: &'a str, value: &'a [u8]) -> Self {
        self.add_header(key, value);
        self
    }

    /// Add a header name & value.
    /// May be called multiple times to add multiple different headers.
    ///
    /// All request headers may be added here, any headers not mentioned
    /// in the jws signature header will be ignored unless required using
    /// [`Verifier::require_header`].
    pub fn add_header(&mut self, key: &'a str, value: &'a [u8]) {
        self.headers.insert(HeaderName(key), value);
    }

    /// Appends multiple header names & values.
    ///
    /// All request headers may be added here, any headers not mentioned
    /// in the jws signature header will be ignored unless required using
    /// [`Verifier::require_header`].
    ///
    /// # Example
    /// ```
    /// # let key = &[];
    /// truelayer_signing::verify_with_pem(key)
    ///     .headers([("X-Head-A", "123".as_bytes()), ("X-Head-B", "345".as_bytes())]);
    /// ```
    pub fn headers(mut self, headers: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Self {
        self.headers
            .extend(headers.into_iter().map(|(k, v)| (HeaderName(k), v)));
        self
    }

    /// Require a header name that must be included in the `Tl-Signature`.
    /// May be called multiple times to add multiple required headers.
    ///
    /// Signatures missing these will fail verification.
    pub fn require_header(mut self, key: &'a str) -> Self {
        self.required_headers.insert(HeaderName(key));
        self
    }

    /// Sets whether v1 body-only signatures are allowed to pass verification.
    /// Default `false`.
    ///
    /// `true` means both v1 & v2 signatures are allowed.
    pub fn allow_v1(mut self, allow: bool) -> Self {
        self.allow_v1 = allow;
        self
    }

    /// Verify the given `Tl-Signature` header value.
    ///
    /// Supports v1 (body only) & v2 full request signatures.
    ///
    /// Returns `Err(_)` if verification fails.
    pub fn verify(&self, tl_signature: &str) -> Result<(), Error> {
        let public_key =
            openssl::parse_ec_public_key(self.public_key).map_err(Error::InvalidKey)?;

        let (jws_header, header_b64, signature) = parse_tl_signature(tl_signature)?;

        if jws_header.alg != "ES512" {
            return Err(Error::JwsError(anyhow!("unexpected header alg")));
        }

        if jws_header.tl_version.is_empty() || jws_header.tl_version == "1" {
            if !self.allow_v1 {
                return Err(Error::JwsError(anyhow!("v1 signature not allowed")));
            }

            // v1 signature: body only
            let payload = format!("{}.{}", header_b64, self.body.to_url_safe_base64());
            openssl::verify_es512(&public_key, payload.as_bytes(), &signature)
                .map_err(Error::JwsError)?;
            return Ok(());
        }

        // check and order all required headers
        let ordered_headers = jws_header
            .filter_headers(&self.headers)
            .map_err(Error::JwsError)?;

        // fail if signature is missing a required header
        if let Some(header) = self
            .required_headers
            .iter()
            .find(|h| !ordered_headers.contains_key(*h))
        {
            return Err(Error::JwsError(anyhow!(
                "signature is missing required header {}",
                header
            )));
        }

        // reconstruct the payload as it would have been signed
        let signing_payload =
            build_v2_signing_payload(self.method, self.path, &ordered_headers, self.body);
        let payload = format!("{}.{}", header_b64, signing_payload.to_url_safe_base64());
        openssl::verify_es512(&public_key, payload.as_bytes(), &signature)
            .map_err(Error::JwsError)?;

        Ok(())
    }
}

/// Parse a tl signature header value into `(header, header_base64, signature)`.
pub(crate) fn parse_tl_signature(tl_signature: &str) -> Result<(JwsHeader, &str, Vec<u8>), Error> {
    let (header_b64, signature_b64) = tl_signature
        .split_once("..")
        .ok_or_else(|| Error::JwsError(anyhow!("invalid signature format")))?;

    let header: JwsHeader = serde_json::from_slice(
        &header_b64
            .decode_url_safe_base64()
            .map_err(|e| Error::JwsError(anyhow!("header decode failed: {}", e)))?,
    )
    .map_err(|e| Error::JwsError(anyhow!("header decode failed: {}", e)))?;
    let signature = signature_b64
        .decode_url_safe_base64()
        .map_err(|e| Error::JwsError(anyhow!("signature decode failed: {}", e)))?;
    Ok((header, header_b64, signature))
}
