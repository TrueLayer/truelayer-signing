//! Produce & verify TrueLayer API `Tl-Signature` request headers.
mod base64;
mod http;
mod jws;
mod openssl;
mod sign;
mod verify;

pub use http::Method;
pub use jws::{JwsAlgorithm, JwsHeader, TlVersion};
pub use sign::{CustomSigner, Signer, SignerBuilder};
use verify::PublicKey;
pub use verify::{CustomVerifier, Verifier, VerifierBuilder};

/// A utility unit type to denote an item hasn't been set.
pub struct Unset;

/// Start building a request `Tl-Signature` header value using private key
/// pem data & the key's `kid`.
///
/// # Example
/// ```no_run
/// # fn main() -> Result<(), truelayer_signing::Error> {
/// # let (kid, private_key, idempotency_key, body) = unimplemented!();
/// let tl_signature = truelayer_signing::sign_with_pem(kid, private_key)
///     .method(truelayer_signing::Method::Post)
///     .path("/payouts")
///     .header("Idempotency-Key", idempotency_key)
///     .body(body)
///     .build_signer()
///     .sign()?;
/// # Ok(()) }
/// ```
pub fn sign_with_pem<'a>(
    kid: &'a str,
    private_key_pem: &'a [u8],
) -> SignerBuilder<'a, &'a str, &'a [u8], Unset, Unset, Unset> {
    SignerBuilder::build_with_pem(kid, private_key_pem)
}

/// Start building a `Tl-Signature` header verifier using public key pem data.
///
/// # Example
/// ```no_run
/// # fn main() -> Result<(), truelayer_signing::Error> {
/// # let (public_key, idempotency_key, body, tl_signature) = unimplemented!();
/// truelayer_signing::verify_with_pem(public_key)
///     .method(truelayer_signing::Method::Post)
///     .path("/payouts")
///     .require_header("Idempotency-Key")
///     .header("Idempotency-Key", idempotency_key)
///     .body(body)
///     .build_verifier()
///     .verify(tl_signature)?;
/// # Ok(()) }
/// ```
pub fn verify_with_pem(
    public_key_pem: &[u8],
) -> VerifierBuilder<'_, PublicKey<'_>, Unset, Unset, Unset> {
    VerifierBuilder::pem(public_key_pem)
}

/// Start building a `Tl-Signature` header verifier using public key JWKs JSON response data.
///
/// See <https://datatracker.ietf.org/doc/html/rfc7517>.
///
/// # Example
/// ```no_run
/// # fn main() -> Result<(), truelayer_signing::Error> {
/// # let (jwks, body, tl_signature) = unimplemented!();
/// # let headers: Vec<(&str, &[u8])> = unimplemented!();
/// // jwks json of form: {"keys":[...]}
/// truelayer_signing::verify_with_jwks(jwks)
///     .method(truelayer_signing::Method::Post)
///     .path("/webhook")
///     .headers(headers)
///     .body(body)
///     .build_verifier()
///     .verify(tl_signature)?;
/// # Ok(()) }
/// ```
pub fn verify_with_jwks(jwks: &[u8]) -> VerifierBuilder<'_, PublicKey<'_>, Unset, Unset, Unset> {
    VerifierBuilder::jwks(jwks)
}

/// Extract [`JwsHeader`] info from a `Tl-Signature` header value.
///
/// This can then be used to pick a verification key using the `kid` etc.
pub fn extract_jws_header(tl_signature: &str) -> Result<JwsHeader, Error> {
    Ok(verify::parse_tl_signature(tl_signature)?.header)
}

/// Sign/verification error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Key data is invalid.
    #[error("invalid key: {0}")]
    InvalidKey(anyhow::Error),
    /// JWS signature generation or verification failed.
    #[error("jws signing/verification failed: {0}")]
    JwsError(anyhow::Error),
    /// Other error.
    #[error("Error: {0}")]
    Other(anyhow::Error),
}
