use anyhow::anyhow;
use indexmap::{IndexMap, IndexSet};

use crate::{base64::ToUrlSafeBase64, http::HeaderName, sign::build_v2_signing_payload, Error};

use super::parse_tl_signature;

pub struct CustomVerifier<'a> {
    pub(crate) body: &'a [u8],
    pub(crate) method: &'static str,
    pub(crate) path: &'a str,
    pub(crate) headers: IndexMap<HeaderName<'a>, &'a [u8]>,
    pub(crate) required_headers: IndexSet<HeaderName<'a>>,
}

impl<'a> CustomVerifier<'a> {
    pub fn verify_with(
        &self,
        tl_signature: &str,
        mut verify_fn: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let (jws_header, header_b64, signature) = parse_tl_signature(tl_signature)?;

        if jws_header.alg != "ES512" {
            return Err(Error::JwsError(anyhow!("unexpected header alg")));
        }

        // check and order all required headers
        let ordered_headers = jws_header
            .filter_headers(&self.headers)
            .map_err(Error::JwsError)?;

        // fail if signature is missing a required header
        if let Some(header) = self
            .required_headers
            .iter()
            .find(|h| !ordered_headers.contains_key(*h))
        {
            return Err(Error::JwsError(anyhow!(
                "signature is missing required header {}",
                header
            )));
        }

        // reconstruct the payload as it would have been signed
        let signing_payload =
            build_v2_signing_payload(self.method, self.path, &ordered_headers, self.body, false);
        let payload = format!("{header_b64}.{}", signing_payload.to_url_safe_base64());

        verify_fn(payload.as_bytes(), signature.as_slice()).or_else(|e| {
            // try again with/without a trailing slash (#80)
            let (path, slash) = match self.path {
                p if p.ends_with('/') => (&p[..p.len() - 1], false),
                p => (p, true),
            };
            let signing_payload =
                build_v2_signing_payload(self.method, path, &ordered_headers, self.body, slash);
            let payload = format!("{header_b64}.{}", signing_payload.to_url_safe_base64());
            // use original error if both fail
            verify_fn(payload.as_bytes(), signature.as_slice()).map_err(|_| e)
        })
    }
}
