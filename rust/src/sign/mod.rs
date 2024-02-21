mod custom_signer;
mod signer_v1;

use indexmap::IndexMap;
use std::{fmt, marker::PhantomData};

use crate::{base64::ToUrlSafeBase64, common::Unset, http::HeaderName, openssl, Error, Get, Post};

pub use self::custom_signer::CustomSigner;
use self::signer_v1::SignerV1;

#[derive(Default)]
pub struct SignerBuilder<'a, Kid, Pk, Body, Method, Path> {
    kid: Kid,
    private_key: Pk,
    body: Body,
    method: Method,
    path: Path,
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
    pub fn kid(self, kid: &str) -> SignerBuilder<'a, &str, Pk, B, M, P> {
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
    pub fn private_key(self, private_key: &[u8]) -> SignerBuilder<'a, K, &[u8], B, M, P> {
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
    pub fn method<M>(self) -> SignerBuilder<'a, K, Pk, B, PhantomData<M>, P> {
        SignerBuilder {
            kid: self.kid,
            private_key: self.private_key,
            body: self.body,
            method: PhantomData,
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
        assert!(
            path.starts_with('/'),
            "Invalid path \"{path}\" must start with '/'"
        );
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
        self.headers.insert(HeaderName(key), value);
        self
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

impl<'a, Pk> SignerBuilder<'a, &'a str, Pk, Unset, PhantomData<Get>, &'a str> {
    pub fn build_custom_signer(self) -> CustomSigner<'a> {
        CustomSigner {
            kid: self.kid,
            body: &[],
            method: Get::name(),
            path: self.path,
            headers: self.headers,
            jws_jku: self.jws_jku,
        }
    }
}

impl<'a, Pk> SignerBuilder<'a, &'a str, Pk, &'a [u8], PhantomData<Post>, &'a str> {
    pub fn build_custom_signer(self) -> CustomSigner<'a> {
        CustomSigner {
            kid: self.kid,
            body: self.body,
            method: Post::name(),
            path: self.path,
            headers: self.headers,
            jws_jku: self.jws_jku,
        }
    }
}

impl<'a> SignerBuilder<'a, &'a str, &'a [u8], &'a [u8], Unset, Unset> {
    pub fn build_v1_signer(self) -> SignerV1<'a> {
        SignerV1 {
            private_key: self.private_key,
            kid: self.kid,
            body: self.body,
            jws_jku: self.jws_jku,
        }
    }
}

impl<'a> SignerBuilder<'a, &'a str, &'a [u8], Unset, PhantomData<Get>, &'a str> {
    pub fn build_signer(self) -> Signer<'a> {
        Signer {
            private_key: self.private_key,
            base: CustomSigner {
                kid: self.kid,
                body: &[],
                method: Get::name(),
                path: self.path,
                headers: self.headers,
                jws_jku: self.jws_jku,
            },
        }
    }
}

impl<'a> SignerBuilder<'a, &'a str, &'a [u8], &'a [u8], PhantomData<Post>, &'a str> {
    pub fn build_signer(self) -> Signer<'a> {
        Signer {
            private_key: self.private_key,
            base: CustomSigner {
                kid: self.kid,
                body: self.body,
                method: Post::name(),
                path: self.path,
                headers: self.headers,
                jws_jku: self.jws_jku,
            },
        }
    }
}

/// Builder to generate a `Tl-Signature` header value using a private key.
///
/// See [`crate::sign_with_pem`] for examples.
pub struct Signer<'a> {
    base: CustomSigner<'a>,
    private_key: &'a [u8],
}

/// Debug does not display key info.
impl fmt::Debug for Signer<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Signer")
    }
}

impl<'a> Signer<'a> {
    /// Produce a JWS `Tl-Signature` v2 header value.
    pub fn sign(self) -> Result<String, Error> {
        let private_key =
            openssl::parse_ec_private_key(self.private_key).map_err(Error::InvalidKey)?;
        self.base.sign_with(|bytes| {
            openssl::sign_es512(&private_key, bytes)
                .map(|sig| sig.to_url_safe_base64())
                .map_err(Error::JwsError)
        })
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
