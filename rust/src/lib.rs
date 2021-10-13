//! Produce & verify TrueLayer API `Tl-Signature` request headers.
//!
//! # Example
//! ```no_run
//! # fn main() -> Result<(), truelayer_request_signature::Error> {
//! # let (kid, private_key, idempotency_key, body) = unimplemented!();
//! // `Tl-Signature` value to send with the request.
//! let tl_signature = truelayer_request_signature::sign_with_pem(kid, private_key)
//!     .method("POST")
//!     .path("/payouts")
//!     .header("Idempotency-Key", idempotency_key)
//!     .body(body)
//!     .sign()?;
//! # Ok(()) }
//! ```
mod base64;
mod http;
mod jws;
mod openssl;
mod sign;
mod verify;

pub use jws::JwsHeader;
pub use sign::Signer;
pub use verify::Verifier;

/// Start building a request `Tl-Signature` header value using private key
/// pem data & the key's `kid`.
///
/// # Example
/// ```no_run
/// # fn main() -> Result<(), truelayer_request_signature::Error> {
/// # let (kid, private_key, idempotency_key, body) = unimplemented!();
/// let tl_signature = truelayer_request_signature::sign_with_pem(kid, private_key)
///     .method("POST")
///     .path("/payouts")
///     .header("Idempotency-Key", idempotency_key)
///     .body(body)
///     .sign()?;
/// # Ok(()) }
/// ```
pub fn sign_with_pem<'a>(kid: &'a str, private_key_pem: &'a str) -> Signer<'a> {
    Signer::new(kid, private_key_pem)
}

/// Start building a `Tl-Signature` header verifier using public key pem data.
///
/// # Example
/// ```no_run
/// # fn main() -> Result<(), truelayer_request_signature::Error> {
/// # let (public_key, idempotency_key, body, tl_signature) = unimplemented!();
/// truelayer_request_signature::verify_with_pem(public_key)
///     .method("POST")
///     .path("/payouts")
///     .require_header("Idempotency-Key")
///     .header("Idempotency-Key", idempotency_key)
///     .body(body)
///     .verify(tl_signature)?;
/// # Ok(()) }
/// ```
pub fn verify_with_pem(public_key_pem: &str) -> Verifier<'_> {
    Verifier::new(public_key_pem)
}

/// Extract [`JwsHeader`] info from a `Tl-Signature` header value.
///
/// This can then be used to pick a verification key using the `kid` etc.
pub fn extract_jws_header(tl_signature: &str) -> Result<JwsHeader, Error> {
    Ok(verify::parse_tl_signature(tl_signature)?.0)
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
}
