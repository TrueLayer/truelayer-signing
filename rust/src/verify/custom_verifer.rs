use std::fmt;

use anyhow::anyhow;
use indexmap::{IndexMap, IndexSet};

use crate::{base64::ToUrlSafeBase64, http::HeaderName, sign::build_v2_signing_payload, Error};

use super::{parse_tl_signature, ParsedTlSignature};

/// A `Tl-Signature` Verifier for custom signature verification.
pub struct CustomVerifier<'a> {
    pub(crate) body: &'a [u8],
    pub(crate) method: &'static str,
    pub(crate) path: &'a str,
    pub(crate) headers: IndexMap<HeaderName<'a>, &'a [u8]>,
    pub(crate) required_headers: IndexSet<HeaderName<'a>>,
}

/// Debug does not display key info.
impl fmt::Debug for CustomVerifier<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Verifier")
    }
}

impl<'a> CustomVerifier<'a> {
    pub fn verify_with(
        self,
        tl_signature: &'a str,
        verify_fn: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let parsed_tl_signature = parse_tl_signature(tl_signature)?;
        self.verify_parsed_with(parsed_tl_signature, verify_fn)
    }

    pub(crate) fn verify_parsed_with(
        self,
        tl_signature: ParsedTlSignature<'a>,
        mut verify_fn: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let ParsedTlSignature {
            header: jws_header,
            header_b64,
            signature,
        } = tl_signature;

        match jws_header.tl_version {
            Some(version) if version != "2" => {
                return Err(Error::JwsError(anyhow!("unexpected header tl_version")))
            }
            None => return Err(Error::JwsError(anyhow!("missing header tl_version"))),
            _ => {}
        }

        if jws_header.alg != "ES512" {
            return Err(Error::JwsError(anyhow!("unexpected header alg")));
        }

        // check and order all included headers
        let ordered_headers = jws_header
            .filter_headers(&self.headers)
            .map_err(Error::JwsError)?
            .ok_or_else(|| Error::JwsError(anyhow!("missing headers tl_headers")))?;

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
