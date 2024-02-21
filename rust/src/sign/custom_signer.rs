use std::future::Future;

use indexmap::IndexMap;

use crate::{base64::ToUrlSafeBase64, http::HeaderName, Error, JwsHeader};

use super::build_v2_signing_payload;

pub struct CustomSigner<'a> {
    pub(crate) kid: &'a str,
    pub(crate) body: &'a [u8],
    pub(crate) method: &'static str,
    pub(crate) path: &'a str,
    pub(crate) headers: IndexMap<HeaderName<'a>, &'a [u8]>,
    pub(crate) jws_jku: Option<&'a str>,
}

impl<'a> CustomSigner<'a> {
    fn build_jws_header_and_payload(&self) -> Result<(String, String), Error> {
        let jws_header = JwsHeader::new_v2(self.kid, &self.headers, self.jws_jku);
        let jws_header_b64 = serde_json::to_string(&jws_header)
            .map_err(|e| Error::JwsError(e.into()))?
            .to_url_safe_base64();

        let signing_payload =
            build_v2_signing_payload(self.method, self.path, &self.headers, self.body, false);

        Ok((jws_header_b64, signing_payload.to_url_safe_base64()))
    }

    /// Produce a JWS `Tl-Signature` v2 header value.
    pub fn sign_with(
        self,
        sign_fn: impl FnOnce(&[u8]) -> Result<String, Error>,
    ) -> Result<String, Error> {
        let (jws_header, payload) = self.build_jws_header_and_payload()?;
        let sig_payload = format!("{}.{}", jws_header, &payload);
        let signature = sign_fn(sig_payload.as_bytes())?;
        Ok(format!("{}..{}", jws_header, signature))
    }

    /// Produce a JWS `Tl-Signature` v2 header value.
    pub async fn async_sign_with<F, Fut>(self, sign_fn: F) -> Result<String, Error>
    where
        F: FnOnce(&[u8]) -> Fut,
        Fut: Future<Output = Result<String, Error>>,
    {
        let (jws_header, payload) = self.build_jws_header_and_payload()?;
        let sig_payload = format!("{}.{}", jws_header, payload);
        let signature = sign_fn(sig_payload.as_bytes()).await?;
        Ok(format!("{}..{}", jws_header, signature))
    }
}
