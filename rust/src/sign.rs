use crate::{base64::ToUrlSafeBase64, http::HeaderName, jws::JwsHeader, openssl, Error};
use indexmap::IndexMap;
use std::{fmt, future::Future};

pub struct Unset;

#[derive(Default)]
pub struct SignerBuilder<'a, K, Pk, B, M, P> {
    kid: K,
    private_key: Pk,
    body: B,
    method: M,
    path: P,
    headers: IndexMap<HeaderName<'a>, &'a [u8]>,
    jws_jku: Option<&'a str>,
}

impl<K, Pk, B, M, P> fmt::Debug for SignerBuilder<'_, K, Pk, B, M, P> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Signer")
    }
}

impl<'a> SignerBuilder<'a, Unset, Unset, Unset, Unset, Unset> {
    pub fn new() -> Self {
        SignerBuilder {
            kid: Unset,
            private_key: Unset,
            body: Unset,
            method: Unset,
            path: Unset,
            headers: <_>::default(),
            jws_jku: <_>::default(),
        }
    }
}

impl<'a, Pk, B, M, P> SignerBuilder<'a, Unset, Pk, B, M, P> {
    pub fn set_kid(self, kid: &str) -> SignerBuilder<'a, &str, Pk, B, M, P> {
        SignerBuilder {
            kid,
            private_key: self.private_key,
            body: self.body,
            method: self.method,
            path: self.path,
            headers: self.headers,
            jws_jku: self.jws_jku,
        }
    }
}

impl<'a, K, B, M, P> SignerBuilder<'a, K, Unset, B, M, P> {
    pub fn set_private_key(self, private_key: &[u8]) -> SignerBuilder<'a, K, &[u8], B, M, P> {
        SignerBuilder {
            kid: self.kid,
            private_key,
            body: self.body,
            method: self.method,
            path: self.path,
            headers: self.headers,
            jws_jku: self.jws_jku,
        }
    }
}

impl<'a, K, Pk, M, P> SignerBuilder<'a, K, Pk, Unset, M, P> {
    /// Add the full request body.
    ///
    /// Note: This **must** be identical to what is sent with the request.
    pub fn body(self, body: &[u8]) -> SignerBuilder<'a, K, Pk, &[u8], M, P> {
        SignerBuilder {
            kid: self.kid,
            private_key: self.private_key,
            body,
            method: self.method,
            path: self.path,
            headers: self.headers,
            jws_jku: self.jws_jku,
        }
    }
}

impl<'a, K, Pk, B, P> SignerBuilder<'a, K, Pk, B, Unset, P> {
    /// Add the request method, defaults to `"POST"` if unspecified.
    pub fn method(self, method: &str) -> SignerBuilder<'a, K, Pk, B, &str, P> {
        SignerBuilder {
            kid: self.kid,
            private_key: self.private_key,
            body: self.body,
            method,
            path: self.path,
            headers: self.headers,
            jws_jku: self.jws_jku,
        }
    }
}

impl<'a, K, Pk, B, M> SignerBuilder<'a, K, Pk, B, M, Unset> {
    /// Add the request absolute path starting with a leading `/` and without
    /// any trailing slashes.
    pub fn path(self, path: &str) -> SignerBuilder<'a, K, Pk, B, M, &str> {
        SignerBuilder {
            kid: self.kid,
            private_key: self.private_key,
            body: self.body,
            method: self.method,
            path,
            headers: self.headers,
            jws_jku: self.jws_jku,
        }
    }
}

impl<'a, K, Pk, B, M, P> SignerBuilder<'a, K, Pk, B, M, P> {
    /// Add a header name & value.
    /// May be called multiple times to add multiple different headers.
    ///
    /// Warning: Only a single value per header name is supported.
    pub fn header(mut self, key: &'a str, value: &'a [u8]) -> Self {
        self.add_header(key, value);
        self
    }

    /// Add a header name & value.
    /// May be called multiple times to add multiple different headers.
    ///
    /// Warning: Only a single value per header name is supported.
    pub fn add_header(&mut self, key: &'a str, value: &'a [u8]) {
        self.headers.insert(HeaderName(key), value);
    }

    /// Appends multiple header names & values.
    ///
    /// Warning: Only a single value per header name is supported.
    pub fn headers(mut self, headers: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Self {
        self.headers
            .extend(headers.into_iter().map(|(k, v)| (HeaderName(k), v)));
        self
    }

    /// Sets the jws header `jku` JSON Web Key URL.
    ///
    /// Note: This is not generally required when calling APIs,
    /// but is set on webhook signatures.
    pub fn jku(mut self, jku: &'a str) -> Self {
        self.jws_jku = Some(jku);
        self
    }
}

impl<'a, Pk> SignerBuilder<'a, &'a str, Pk, &'a [u8], &'a str, &'a str> {
    pub fn build_custom_signer(self) -> CustomSigner<'a> {
        CustomSigner {
            kid: self.kid,
            body: self.body,
            method: self.method,
            path: self.path,
            headers: self.headers,
            jws_jku: self.jws_jku,
        }
    }
}

impl<'a> SignerBuilder<'a, &'a str, &'a [u8], &'a [u8], &'a str, &'a str> {
    pub fn build_signer(self) -> Signer<'a> {
        Signer {
            kid: self.kid,
            private_key: self.private_key,
            body: self.body,
            method: self.method,
            path: self.path,
            headers: self.headers,
            jws_jku: self.jws_jku,
        }
    }
}

pub struct CustomSigner<'a> {
    kid: &'a str,
    body: &'a [u8],
    method: &'a str,
    path: &'a str,
    headers: IndexMap<HeaderName<'a>, &'a [u8]>,
    jws_jku: Option<&'a str>,
}

impl<'a> CustomSigner<'a> {
    fn build_jws_header_and_payload(&self) -> Result<String, Error> {
        let jws_header = JwsHeader::new_v2(self.kid, &self.headers, self.jws_jku.map(|u| u.into()));
        let jws_header_b64 = serde_json::to_string(&jws_header)
            .map_err(|e| Error::JwsError(e.into()))?
            .to_url_safe_base64();

        let signing_payload =
            build_v2_signing_payload(self.method, self.path, &self.headers, self.body, false);

        Ok(format!(
            "{}.{}",
            jws_header_b64,
            signing_payload.to_url_safe_base64()
        ))
    }

    /// Produce a JWS `Tl-Signature` v2 header value.
    pub fn sign_with(
        &self,
        sign_fn: impl FnOnce(&[u8]) -> Result<String, Error>,
    ) -> Result<String, Error> {
        let jws_header_and_payload = self.build_jws_header_and_payload()?;
        let signature = sign_fn(jws_header_and_payload.as_bytes())?;
        Ok(format!(
            "{}..{}",
            jws_header_and_payload.split('.').next().unwrap(),
            signature
        ))
    }

    /// Produce a JWS `Tl-Signature` v2 header value.
    pub async fn async_sign_with<F, Fut>(&self, sign_fn: F) -> Result<String, Error>
    where
        F: FnOnce(&[u8]) -> Fut,
        Fut: Future<Output = Result<String, Error>>,
    {
        let jws_header_and_payload = self.build_jws_header_and_payload()?;
        let signature = sign_fn(jws_header_and_payload.as_bytes()).await?;
        Ok(format!(
            "{}..{}",
            jws_header_and_payload.split('.').next().unwrap(),
            signature
        ))
    }
}

/// Builder to generate a `Tl-Signature` header value using a private key.
///
/// See [`crate::sign_with_pem`] for examples.
pub struct Signer<'a> {
    kid: &'a str,
    private_key: &'a [u8],
    body: &'a [u8],
    method: &'a str,
    path: &'a str,
    headers: IndexMap<HeaderName<'a>, &'a [u8]>,
    jws_jku: Option<&'a str>,
}

/// Debug does not display key info.
impl fmt::Debug for Signer<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Signer")
    }
}

impl<'a> Signer<'a> {
    pub(crate) fn new(kid: &'a str, private_key_pem: &'a [u8]) -> Self {
        Self {
            kid,
            private_key: private_key_pem,
            body: &[],
            method: "POST",
            path: "",
            headers: <_>::default(),
            jws_jku: <_>::default(),
        }
    }

    /// Add the full request body.
    ///
    /// Note: This **must** be identical to what is sent with the request.
    ///
    /// # Example
    /// ```
    /// # let (kid, key) = ("", &[]);
    /// truelayer_signing::sign_with_pem(kid, key)
    ///     .body(b"{...}");
    /// ```
    pub fn body(mut self, body: &'a [u8]) -> Self {
        self.body = body;
        self
    }

    /// Add the request method, defaults to `"POST"` if unspecified.
    ///
    /// # Example
    /// ```
    /// # let (kid, key) = ("", &[]);
    /// truelayer_signing::sign_with_pem(kid, key)
    ///     .method("POST");
    /// ```
    pub fn method(mut self, method: &'a str) -> Self {
        self.method = method;
        self
    }

    /// Add the request absolute path starting with a leading `/` and without
    /// any trailing slashes.
    ///
    /// # Panics
    /// If `path` does not start with a '/' char.
    ///
    /// # Example
    /// ```
    /// # let (kid, key) = ("", &[]);
    /// truelayer_signing::sign_with_pem(kid, key)
    ///     .path("/payouts");
    /// ```
    pub fn path(mut self, path: &'a str) -> Self {
        assert!(
            path.starts_with('/'),
            "Invalid path \"{path}\" must start with '/'"
        );
        self.path = path;
        self
    }

    /// Add a header name & value.
    /// May be called multiple times to add multiple different headers.
    ///
    /// Warning: Only a single value per header name is supported.
    ///
    /// # Example
    /// ```
    /// # let (kid, key) = ("", &[]);
    /// truelayer_signing::sign_with_pem(kid, key)
    ///     .header("Idempotency-Key", b"60df4d00-9778-4297-be6d-817d7a6d27bb");
    /// ```
    pub fn header(mut self, key: &'a str, value: &'a [u8]) -> Self {
        self.add_header(key, value);
        self
    }

    /// Add a header name & value.
    /// May be called multiple times to add multiple different headers.
    ///
    /// Warning: Only a single value per header name is supported.
    ///
    /// # Example
    /// ```
    /// # let mut signer = truelayer_signing::sign_with_pem("", &[]);
    /// signer.add_header("Idempotency-Key", b"60df4d00-9778-4297-be6d-817d7a6d27bb");
    /// ```
    pub fn add_header(&mut self, key: &'a str, value: &'a [u8]) {
        self.headers.insert(HeaderName(key), value);
    }

    /// Appends multiple header names & values.
    ///
    /// Warning: Only a single value per header name is supported.
    ///
    /// # Example
    /// ```
    /// # let (kid, key) = ("", &[]);
    /// truelayer_signing::sign_with_pem(kid, key)
    ///     .headers([("X-Head-A", "123".as_bytes()), ("X-Head-B", "345".as_bytes())]);
    /// ```
    pub fn headers(mut self, headers: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Self {
        self.headers
            .extend(headers.into_iter().map(|(k, v)| (HeaderName(k), v)));
        self
    }

    /// Sets the jws header `jku` JSON Web Key URL.
    ///
    /// Note: This is not generally required when calling APIs,
    /// but is set on webhook signatures.
    pub fn jku(mut self, jku: &'a str) -> Self {
        self.jws_jku = Some(jku);
        self
    }

    /// Produce a JWS `Tl-Signature` v1 header value, signing just the request body.
    ///
    /// Any specified method, path & headers will be ignored.
    ///
    /// In general full request signing should be preferred, see [`Signer::sign`].
    pub fn sign_body_only(&self) -> Result<String, Error> {
        let private_key =
            openssl::parse_ec_private_key(self.private_key).map_err(Error::InvalidKey)?;

        let jws_header = {
            let mut header = serde_json::json!({
                "alg": "ES512",
                "kid": self.kid,
            });
            if let Some(jku) = self.jws_jku {
                header["jku"] = jku.into();
            }
            serde_json::to_string(&header)
                .map_err(|e| Error::JwsError(e.into()))?
                .to_url_safe_base64()
        };
        let jws_header_and_payload = format!("{}.{}", jws_header, self.body.to_url_safe_base64());

        let signature = openssl::sign_es512(&private_key, jws_header_and_payload.as_bytes())
            .map_err(Error::JwsError)?
            .to_url_safe_base64();

        let mut jws = jws_header;
        jws.push_str("..");
        jws.push_str(&signature);

        Ok(jws)
    }

    /// Produce a JWS `Tl-Signature` v2 header value.
    pub fn sign(&self) -> Result<String, Error> {
        let private_key =
            openssl::parse_ec_private_key(self.private_key).map_err(Error::InvalidKey)?;

        let jws_header = JwsHeader::new_v2(self.kid, &self.headers, self.jws_jku.map(|u| u.into()));
        let jws_header_b64 = serde_json::to_string(&jws_header)
            .map_err(|e| Error::JwsError(e.into()))?
            .to_url_safe_base64();

        let signing_payload =
            build_v2_signing_payload(self.method, self.path, &self.headers, self.body, false);

        let jws_header_and_payload = format!(
            "{}.{}",
            jws_header_b64,
            signing_payload.to_url_safe_base64()
        );
        let signature = openssl::sign_es512(&private_key, jws_header_and_payload.as_bytes())
            .map_err(Error::JwsError)?
            .to_url_safe_base64();

        let mut jws = jws_header_b64;
        jws.push_str("..");
        jws.push_str(&signature);

        Ok(jws)
    }
}

/// Build a v2 signing payload.
///
/// # Example
/// ```txt
/// POST /test-signature
/// Idempotency-Key: 619410b3-b00c-406e-bb1b-2982f97edb8b
/// {"bar":123}
/// ```
pub(crate) fn build_v2_signing_payload(
    method: &str,
    path: &str,
    headers: &IndexMap<HeaderName<'_>, &[u8]>,
    body: &[u8],
    add_path_trailing_slash: bool,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(method.to_ascii_uppercase().as_bytes());
    payload.push(b' ');
    payload.extend(path.as_bytes());
    if add_path_trailing_slash {
        payload.push(b'/');
    }
    payload.push(b'\n');
    for (h_name, h_val) in headers {
        payload.extend(h_name.0.as_bytes());
        payload.extend(b": ");
        payload.extend(*h_val);
        payload.push(b'\n');
    }
    payload.extend(body);
    payload
}
