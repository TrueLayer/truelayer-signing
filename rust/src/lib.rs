//! Produce & verify TrueLayer API `Tl-Signature` request headers.
mod base64;
mod common;
mod http;
mod jws;
mod openssl;
mod sign;
mod verify;

pub use http::{Get, Post};
pub use jws::JwsHeader;
pub use sign::{CustomSigner, Signer, SignerBuilder};
pub use verify::{CustomVerifier, Verifier, VerifierBuilder};

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
    /// Other error.
    #[error("Error: {0}")]
    Other(anyhow::Error),
}
