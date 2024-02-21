use anyhow::anyhow;

use crate::{base64::ToUrlSafeBase64, openssl, Error};

use super::{parse_tl_signature, PublicKey};

pub struct VerifierV1<'a> {
    pub(crate) public_key: PublicKey<'a>,
    pub(crate) body: &'a [u8],
}

impl<'a> VerifierV1<'a> {
    pub fn verify_body_only(self, tl_signature: &str) -> Result<(), Error> {
        let (jws_header, header_b64, signature) = parse_tl_signature(tl_signature)?;

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
