use std::{fmt, marker::PhantomData};

use anyhow::anyhow;
use indexmap::{IndexMap, IndexSet};

use crate::{
    base64::DecodeUrlSafeBase64, common::Unset, http::HeaderName, openssl, Error, Get, JwsHeader,
    Post,
};

pub use self::custom_verifer::CustomVerifier;
use self::verifier_v1::VerifierV1;

mod custom_verifer;
mod verifier_v1;

#[derive(Default)]
pub struct VerifierBuilder<'a, Pk, Body, Method, Path> {
    public_key: Pk,
    body: Body,
    method: Method,
    path: Path,
    headers: IndexMap<HeaderName<'a>, &'a [u8]>,
    required_headers: IndexSet<HeaderName<'a>>,
}

#[derive(Clone, Copy)]
pub enum PublicKey<'a> {
    /// Public key PEM.
    Pem(&'a [u8]),
    /// JWKs JSON response.
    Jwks(&'a [u8]),
}

/// Debug does not display key info.
impl<Pk, Body, Method, Path> fmt::Debug for VerifierBuilder<'_, Pk, Body, Method, Path> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Verifier")
    }
}

impl<'a> VerifierBuilder<'a, Unset, Unset, Unset, Unset> {
    pub fn new() -> Self {
        VerifierBuilder {
            public_key: Unset,
            body: Unset,
            method: Unset,
            path: Unset,
            headers: <_>::default(),
            required_headers: <_>::default(),
        }
    }
}

impl<'a, Body, Method, Path> VerifierBuilder<'a, Unset, Body, Method, Path> {
    pub fn pem(self, pem: &'a [u8]) -> VerifierBuilder<'a, PublicKey<'a>, Body, Method, Path> {
        VerifierBuilder {
            public_key: PublicKey::Pem(pem),
            body: self.body,
            method: self.method,
            path: self.path,
            headers: self.headers,
            required_headers: self.required_headers,
        }
    }

    pub fn jwks(self, jwk: &'a [u8]) -> VerifierBuilder<'a, PublicKey<'a>, Body, Method, Path> {
        VerifierBuilder {
            public_key: PublicKey::Jwks(jwk),
            body: self.body,
            method: self.method,
            path: self.path,
            headers: self.headers,
            required_headers: self.required_headers,
        }
    }
}

impl<'a, Pk, Method, Path> VerifierBuilder<'a, Pk, Unset, Method, Path> {
    pub fn body(self, body: &'a [u8]) -> VerifierBuilder<'a, Pk, &'a [u8], Method, Path> {
        VerifierBuilder {
            public_key: self.public_key,
            body,
            method: self.method,
            path: self.path,
            headers: self.headers,
            required_headers: self.required_headers,
        }
    }
}

impl<'a, Pk, Body, Path> VerifierBuilder<'a, Pk, Body, Unset, Path> {
    pub fn method<M>(self) -> VerifierBuilder<'a, Pk, Body, PhantomData<M>, Path> {
        VerifierBuilder {
            public_key: self.public_key,
            body: self.body,
            method: PhantomData,
            path: self.path,
            headers: self.headers,
            required_headers: self.required_headers,
        }
    }
}

impl<'a, Pk, Body, Method> VerifierBuilder<'a, Pk, Body, Method, Unset> {
    pub fn path(self, path: &'a str) -> VerifierBuilder<'a, Pk, Body, Method, &'a str> {
        assert!(
            path.starts_with('/'),
            "Invalid path \"{path}\" must start with '/'"
        );
        VerifierBuilder {
            public_key: self.public_key,
            body: self.body,
            method: self.method,
            path,
            headers: self.headers,
            required_headers: self.required_headers,
        }
    }
}

impl<'a, Pk, Body, Method, Path> VerifierBuilder<'a, Pk, Body, Method, Path> {
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

    pub fn require_header(mut self, key: &'a str) -> Self {
        self.required_headers.insert(HeaderName(key));
        self
    }
}

impl<'a> VerifierBuilder<'a, PublicKey<'a>, &'a [u8], PhantomData<Get>, &'a str> {
    pub fn build_verifier(self) -> Verifier<'a> {
        Verifier {
            base: CustomVerifier {
                body: self.body,
                method: Get::name(),
                path: self.path,
                headers: self.headers,
                required_headers: self.required_headers,
            },
            public_key: self.public_key,
        }
    }
}

impl<'a> VerifierBuilder<'a, PublicKey<'a>, &'a [u8], PhantomData<Post>, &'a str> {
    pub fn build_verifier(self) -> Verifier<'a> {
        Verifier {
            base: CustomVerifier {
                body: self.body,
                method: Post::name(),
                path: self.path,
                headers: self.headers,
                required_headers: self.required_headers,
            },
            public_key: self.public_key,
        }
    }
}

impl<'a> VerifierBuilder<'a, PublicKey<'a>, &'a [u8], Unset, Unset> {
    pub fn build_v1_verifier(self) -> VerifierV1<'a> {
        VerifierV1 {
            public_key: self.public_key,
            body: self.body,
        }
    }
}

pub struct Verifier<'a> {
    base: CustomVerifier<'a>,
    public_key: PublicKey<'a>,
}

impl<'a> Verifier<'a> {
    pub fn verify(&self, tl_signature: &str) -> Result<(), Error> {
        let (jws_header, _, _) = parse_tl_signature(tl_signature)?;

        let public_key = match self.public_key {
            PublicKey::Pem(pem) => openssl::parse_ec_public_key(pem),
            PublicKey::Jwks(jwks) => openssl::find_and_parse_ec_jwk(&jws_header.kid, jwks),
        }
        .map_err(Error::InvalidKey)?;

        self.base.verify_with(tl_signature, |payload, signature| {
            openssl::verify_es512(&public_key, payload, signature).map_err(Error::JwsError)
        })
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
