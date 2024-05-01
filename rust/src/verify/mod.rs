use std::fmt;

use anyhow::anyhow;
use indexmap::{IndexMap, IndexSet};

use crate::{
    base64::DecodeUrlSafeBase64, common::Unset, http::HeaderName, jws::TlVersion, openssl, Error,
    JwsHeader, Method,
};

pub use self::custom_verifer::CustomVerifier;
use self::verifier_v1::VerifierV1;

mod custom_verifer;
mod verifier_v1;

/// Builder to verify a request against a `Tl-Signature` header.
///
/// # Example
/// ```no_run
/// # fn main() -> Result<(), truelayer_signing::Error> {
/// # let (public_key, idempotency_key, body, tl_signature) = unimplemented!();
/// truelayer_signing::VerifierBuilder::pem(public_key)
///     .method(truelayer_signing::Method::Post)
///     .path("/payouts")
///     .require_header("Idempotency-Key")
///     .header("X-Whatever", b"aoitbeh")
///     .header("Idempotency-Key", idempotency_key)
///     .body(body)
///     .build_verifier()
///     .verify(tl_signature)
///     .expect("verify");
/// # }
/// ```
#[derive(Default)]
pub struct VerifierBuilder<'a, Pk, Body, Method, Path> {
    public_key: Pk,
    body: Body,
    method: Method,
    path: Path,
    headers: IndexMap<HeaderName<'a>, &'a [u8]>,
    required_headers: IndexSet<HeaderName<'a>>,
}

/// Public key for verification.
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

impl<'a> VerifierBuilder<'a, PublicKey<'a>, Unset, Unset, Unset> {
    /// Add public key via pem.
    pub fn pem(pem: &'a [u8]) -> VerifierBuilder<'a, PublicKey<'a>, Unset, Unset, Unset> {
        VerifierBuilder {
            public_key: PublicKey::Pem(pem),
            body: Unset,
            method: Unset,
            path: Unset,
            headers: <_>::default(),
            required_headers: <_>::default(),
        }
    }

    /// Add public key via a jwks.
    pub fn jwks(jwk: &'a [u8]) -> VerifierBuilder<'a, PublicKey<'a>, Unset, Unset, Unset> {
        VerifierBuilder {
            public_key: PublicKey::Jwks(jwk),
            body: Unset,
            method: Unset,
            path: Unset,
            headers: <_>::default(),
            required_headers: <_>::default(),
        }
    }
}

impl<'a, Pk, Method, Path> VerifierBuilder<'a, Pk, Unset, Method, Path> {
    /// Add the full received request body.
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
    /// Add the request method.
    pub fn method(self, method: Method) -> VerifierBuilder<'a, Pk, Body, Method, Path> {
        VerifierBuilder {
            public_key: self.public_key,
            body: self.body,
            method,
            path: self.path,
            headers: self.headers,
            required_headers: self.required_headers,
        }
    }
}

impl<'a, Pk, Body, Method> VerifierBuilder<'a, Pk, Body, Method, Unset> {
    /// Add the request path, e.g. `"/payouts"`.
    ///
    /// # Panics
    /// If `path` does not start with a '/' char.
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
    /// All request headers may be added here, any headers not mentioned
    /// in the jws signature header will be ignored unless required using
    /// [`Verifier::require_header`].
    pub fn header(mut self, key: &'a str, value: &'a [u8]) -> Self {
        self.headers.insert(HeaderName(key), value);
        self
    }

    /// Appends multiple header names & values.
    ///
    /// All request headers may be added here, any headers not mentioned
    /// in the jws signature header will be ignored unless required using
    /// [`Verifier::require_header`].
    ///
    /// # Example
    /// ```no_run
    /// # let public_key = unimplemented!();
    /// truelayer_signing::VerifierBuilder::pem(public_key)
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
}

impl<'a> VerifierBuilder<'a, PublicKey<'a>, &'a [u8], Method, &'a str> {
    /// Build a V2 Verifier see [`Verifier`].
    ///
    /// requires the public key, body, method, and path to be set to call this function.
    pub fn build_verifier(self) -> Verifier<'a> {
        Verifier {
            base: CustomVerifier {
                body: self.body,
                method: self.method.name(),
                path: self.path,
                headers: self.headers,
                required_headers: self.required_headers,
            },
            public_key: self.public_key,
        }
    }
}

impl<'a> VerifierBuilder<'a, PublicKey<'a>, &'a [u8], Unset, Unset> {
    /// Build a V1 Verifier see [`VerifierV1`].
    ///
    /// requires the public key and body to be set to call this function.
    pub fn build_v1_verifier(self) -> VerifierV1<'a> {
        VerifierV1 {
            public_key: self.public_key,
            body: self.body,
        }
    }
}

/// Verify the given `Tl-Signature` header value.
///
/// # Example
/// ```no_run
/// # fn main() -> Result<(), truelayer_signing::Error> {
/// # let (public_key, idempotency_key, body, tl_signature) = unimplemented!();
/// truelayer_signing::VerifierBuilder::pem(public_key)
///     .method(truelayer_signing::Method::Post)
///     .path("/payouts")
///     .require_header("Idempotency-Key")
///     .header("X-Whatever", b"aoitbeh")
///     .header("Idempotency-Key", idempotency_key)
///     .body(body)
///     .build_verifier()
///     .verify(tl_signature)
///     .expect("verify");
/// # }
/// ```
pub struct Verifier<'a> {
    base: CustomVerifier<'a>,
    public_key: PublicKey<'a>,
}

/// Debug does not display key info.
impl fmt::Debug for Verifier<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Verifier")
    }
}

impl<'a> Verifier<'a> {
    /// Verify the given `Tl-Signature` header value.
    ///
    /// Supports v2 full request signatures.
    ///
    /// Returns `Err(_)` if verification fails.
    pub fn verify(self, tl_signature: &'a str) -> Result<(), Error> {
        let parsed_tl_signature = parse_tl_signature(tl_signature)?;
        self.verify_parsed(parsed_tl_signature)
    }

    fn verify_parsed(self, parsed_tl_signature: ParsedTlSignature<'a>) -> Result<(), Error> {
        let public_key = match self.public_key {
            PublicKey::Pem(pem) => openssl::parse_ec_public_key(pem),
            PublicKey::Jwks(jwks) => {
                openssl::find_and_parse_ec_jwk(parsed_tl_signature.header.kid, jwks)
            }
        }
        .map_err(Error::InvalidKey)?;

        self.base
            .verify_parsed_with(parsed_tl_signature, |payload, signature| {
                openssl::verify_es512(&public_key, payload, signature).map_err(Error::JwsError)
            })
    }

    /// Verify the given `Tl-Signature` header value.
    ///
    /// Supports v1 (body only) & v2 full request signatures.
    ///
    /// Returns `Err(_)` if verification fails.
    pub fn verify_v1_or_v2(self, tl_signature: &'a str) -> Result<(), Error> {
        let parsed_tl_signature = parse_tl_signature(tl_signature)?;

        match &parsed_tl_signature.header.tl_version {
            None | Some(TlVersion::V1) => VerifierV1 {
                public_key: self.public_key,
                body: self.base.body,
            }
            .verify_parsed_body_only(parsed_tl_signature),
            Some(TlVersion::V2) => self.verify_parsed(parsed_tl_signature),
        }
    }
}

/// Parsed `Tl-Signature` header value.
pub(crate) struct ParsedTlSignature<'a> {
    pub(crate) header: JwsHeader<'a>,
    pub(crate) header_b64: &'a str,
    pub(crate) signature: Vec<u8>,
}

/// Parse a tl signature header value into `(header, header_base64, signature)`.
pub(crate) fn parse_tl_signature(tl_signature: &str) -> Result<ParsedTlSignature, Error> {
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

    Ok(ParsedTlSignature {
        header,
        header_b64,
        signature,
    })
}
