use std::fmt;

use anyhow::anyhow;

use crate::{base64::ToUrlSafeBase64, openssl, Error, JwsHeader};

use super::{parse_tl_signature, PublicKey};

/// A verifier for a request against a `Tl-Signature` header V1.
pub struct VerifierV1<'a> {
    pub(crate) public_key: PublicKey<'a>,
    pub(crate) body: &'a [u8],
    pub(crate) parsed_tl_sig: Option<(JwsHeader<'a>, &'a str, Vec<u8>)>,
}

/// Debug does not display key info.
impl fmt::Debug for VerifierV1<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Verifier")
    }
}

impl<'a> VerifierV1<'a> {
    /// Verify the given `Tl-Signature` header value.
    ///
    /// Supports v1 (body only) request signatures.
    ///
    /// Returns `Err(_)` if verification fails.
    pub fn verify_body_only(mut self, tl_signature: &'a str) -> Result<(), Error> {
        let (jws_header, header_b64, signature) = unsafe {
            if self.parsed_tl_sig.is_none() {
                self.parsed_tl_sig = Some(parse_tl_signature(tl_signature)?);
            };
            self.parsed_tl_sig.unwrap_unchecked()
        };

        let public_key = match self.public_key {
            PublicKey::Pem(pem) => openssl::parse_ec_public_key(pem),
            PublicKey::Jwks(jwks) => openssl::find_and_parse_ec_jwk(&jws_header.kid, jwks),
        }
        .map_err(Error::InvalidKey)?;

        if jws_header.alg != "ES512" {
            return Err(Error::JwsError(anyhow!("unexpected header alg")));
        }

        // v1 signature: body only
        let payload = format!("{header_b64}.{}", self.body.to_url_safe_base64());
        openssl::verify_es512(&public_key, payload.as_bytes(), &signature).map_err(Error::JwsError)
    }
}
