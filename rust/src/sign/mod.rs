mod custom_signer;
mod signer_v1;

use indexmap::IndexMap;
use std::{fmt, marker::PhantomData};

use crate::{base64::ToUrlSafeBase64, common::Unset, http::HeaderName, openssl, Error, Get, Post};

pub use self::custom_signer::CustomSigner;
use self::signer_v1::SignerV1;

/// Builder to generate a `Tl-Signature` header value.
///
/// # Example
/// ```no_run
/// # fn main() -> Result<(), truelayer_signing::Error> {
/// # let (kid, private_key, idempotency_key, body) = unimplemented!();
/// let tl_signature = truelayer_signing::SignerBuilder::new()
///     .private_key(private_key)
///     .kid(kid)
///     .method::<truelayer_signing::Post>()
///     .path("/payouts")
///     .header("Idempotency-Key", idempotency_key)
///     .body(body)
///     .build_signer()
///     .sign()?;
/// # Ok(()) }
/// ```
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

impl<K, Pk, Body, Method, Path> fmt::Debug for SignerBuilder<'_, K, Pk, Body, Method, Path> {
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

impl<'a, Pk, Body, Method, Path> SignerBuilder<'a, Unset, Pk, Body, Method, Path> {
    /// Add the private key kid.
    pub fn kid(self, kid: &str) -> SignerBuilder<'a, &str, Pk, Body, Method, Path> {
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

impl<'a, K, Body, Method, Path> SignerBuilder<'a, K, Unset, Body, Method, Path> {
    /// Add the private key.
    pub fn private_key(
        self,
        private_key: &[u8],
    ) -> SignerBuilder<'a, K, &[u8], Body, Method, Path> {
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

impl<'a, K, Pk, Method, Path> SignerBuilder<'a, K, Pk, Unset, Method, Path> {
    /// Add the full request body.
    ///
    /// Note: This **must** be identical to what is sent with the request.
    pub fn body(self, body: &[u8]) -> SignerBuilder<'a, K, Pk, &[u8], Method, Path> {
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

impl<'a, K, Pk, Body, Path> SignerBuilder<'a, K, Pk, Body, Unset, Path> {
    /// Add the request method.
    pub fn method<M>(self) -> SignerBuilder<'a, K, Pk, Body, PhantomData<M>, Path> {
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

impl<'a, K, Pk, Body, Method> SignerBuilder<'a, K, Pk, Body, Method, Unset> {
    /// Add the request absolute path starting with a leading `/` and without
    /// any trailing slashes.
    pub fn path(self, path: &str) -> SignerBuilder<'a, K, Pk, Body, Method, &str> {
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

impl<'a, K, Pk, Body, Method, Path> SignerBuilder<'a, K, Pk, Body, Method, Path> {
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

impl<'a> SignerBuilder<'a, &'a str, Unset, Unset, PhantomData<Get>, &'a str> {
    /// Builds a [`CustomSigner`]
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

impl<'a> SignerBuilder<'a, &'a str, Unset, &'a [u8], PhantomData<Post>, &'a str> {
    /// Builds a [`CustomSigner`]
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
    /// Build a V1 Signer see [`SignerV1`].
    ///
    /// Any specified method, path & headers will be ignored.
    ///
    /// In general full request signing should be preferred, see [`Signer`].
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
    /// Build a V2 Signer see [`Signer`].
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
    /// Build a V2 Signer see [`Signer`].
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

/// Signer to generate a `Tl-Signature` header value using a private key.
///
/// # Example
/// ```no_run
/// # fn main() -> Result<(), truelayer_signing::Error> {
/// # let (kid, private_key, idempotency_key, body) = unimplemented!();
/// let tl_signature = truelayer_signing::SignerBuilder::new()
///     .private_key(private_key)
///     .kid(kid)
///     .method::<truelayer_signing::Post>()
///     .path("/payouts")
///     .header("Idempotency-Key", idempotency_key)
///     .body(body)
///     .build_signer()
///     .sign()?;
/// # Ok(()) }
/// ```
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
    payload.extend(method.as_bytes());
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
