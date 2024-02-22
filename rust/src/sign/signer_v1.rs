use crate::{base64::ToUrlSafeBase64, openssl, Error};

/// Produce a JWS `Tl-Signature` v1 header value, signing just the request body.
///
/// Any specified method, path & headers will be ignored.
///
/// In general full request signing should be preferred, see [`Signer::sign`].
pub struct SignerV1<'a> {
    pub(crate) private_key: &'a [u8],
    pub(crate) kid: &'a str,
    pub(crate) body: &'a [u8],
    pub(crate) jws_jku: Option<&'a str>,
}

impl<'a> SignerV1<'a> {
    /// Produce a JWS `Tl-Signature` v1 header value, signing just the request body.
    ///
    /// Any specified method, path & headers will be ignored.
    ///
    /// In general full request signing should be preferred, see [`Signer::sign`].
    pub fn sign_body_only(self) -> Result<String, Error> {
        let private_key =
            openssl::parse_ec_private_key(self.private_key).map_err(Error::InvalidKey)?;

        let jws_header = {
            let mut header = serde_json::json!({
                "alg": "ES512",
                "kid": self.kid,
            });
            if let Some(jku) = self.jws_jku {
                header["jku"] = jku.into();
            }
            serde_json::to_string(&header)
                .map_err(|e| Error::JwsError(e.into()))?
                .to_url_safe_base64()
        };
        let jws_header_and_payload = format!("{}.{}", jws_header, self.body.to_url_safe_base64());

        let signature = openssl::sign_es512(&private_key, jws_header_and_payload.as_bytes())
            .map_err(Error::JwsError)?
            .to_url_safe_base64();

        let mut jws = jws_header;
        jws.push_str("..");
        jws.push_str(&signature);

        Ok(jws)
    }
}
