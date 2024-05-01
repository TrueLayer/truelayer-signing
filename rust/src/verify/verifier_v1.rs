use std::fmt;

use crate::{base64::ToUrlSafeBase64, openssl, Error};

use super::{parse_tl_signature, ParsedTlSignature, PublicKey};

/// A verifier for a request against a `Tl-Signature` header V1.
pub struct VerifierV1<'a> {
    pub(crate) public_key: PublicKey<'a>,
    pub(crate) body: &'a [u8],
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
    pub fn verify_body_only(self, tl_signature: &'a str) -> Result<(), Error> {
        let parsed_tl_signature = parse_tl_signature(tl_signature)?;
        self.verify_parsed_body_only(parsed_tl_signature)
    }

    pub(crate) fn verify_parsed_body_only(
        self,
        tl_signature: ParsedTlSignature<'a>,
    ) -> Result<(), Error> {
        let ParsedTlSignature {
            header: jws_header,
            header_b64,
            signature,
        } = tl_signature;

        let public_key = match self.public_key {
            PublicKey::Pem(pem) => openssl::parse_ec_public_key(pem),
            PublicKey::Jwks(jwks) => openssl::find_and_parse_ec_jwk(&jws_header.kid, jwks),
        }
        .map_err(Error::InvalidKey)?;

        // v1 signature: body only
        let payload = format!("{header_b64}.{}", self.body.to_url_safe_base64());
        openssl::verify_es512(&public_key, payload.as_bytes(), &signature).map_err(Error::JwsError)
    }
}
