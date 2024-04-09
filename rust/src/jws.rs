use std::borrow::Cow;

use crate::http::HeaderName;
use anyhow::anyhow;
use indexmap::{IndexMap, IndexSet};

/// `Tl-Signature` header.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct JwsHeader<'a> {
    /// Algorithm, should be `ES512`.
    pub alg: Cow<'a, str>,
    /// Siging key id.
    pub kid: Cow<'a, str>,
    /// Signing scheme version, e.g. `"2"`.
    ///
    /// Empty implies v1, aka body-only signing.
    #[serde(default)]
    pub tl_version: Cow<'a, str>,
    /// Comma separated ordered headers used in the signature.
    #[serde(default)]
    pub tl_headers: String,
    /// JSON Web Key URL. Used in webhook signatures providing the public key jwk url.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jku: Option<Cow<'a, str>>,
}

impl<'a> JwsHeader<'a> {
    pub(crate) fn new_v2(
        kid: &'a str,
        headers: &IndexMap<HeaderName<'_>, &[u8]>,
        jku: Option<&'a str>,
    ) -> Self {
        let header_keys = headers.keys().fold(String::new(), |mut all, next| {
            if !all.is_empty() {
                all.push(',');
            }
            all.push_str(next.0);
            all
        });
        Self {
            alg: Cow::Borrowed("ES512"),
            kid: Cow::Borrowed(kid),
            tl_version: Cow::Borrowed("2"),
            tl_headers: header_keys,
            jku: jku.map(Cow::Borrowed),
        }
    }

    /// Filter & order headers to match jws header `tl_headers`.
    ///
    /// Returns an `Err(_)` if `headers` is missing any of the declared `tl_headers`.
    pub(crate) fn filter_headers(
        &'a self,
        headers: &IndexMap<HeaderName<'_>, &'a [u8]>,
    ) -> anyhow::Result<IndexMap<HeaderName<'a>, &'a [u8]>> {
        let required_headers: IndexSet<_> = self
            .tl_headers
            .split(',')
            .filter(|h| !h.is_empty())
            .map(HeaderName)
            .collect();

        // populate required headers in jws-header order
        let ordered_headers: IndexMap<_, _> = required_headers
            .iter()
            .map(|h| {
                let hval = headers
                    .get(h)
                    .ok_or_else(|| anyhow!("Missing tl_header `{}` declared in signature", h))?;
                Ok((*h, *hval))
            })
            .collect::<anyhow::Result<_>>()?;

        Ok(ordered_headers)
    }
}
