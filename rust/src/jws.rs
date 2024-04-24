use std::borrow::Cow;

use crate::http::HeaderName;
use indexmap::IndexMap;

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
    pub tl_version: Option<Cow<'a, str>>,
    /// Comma separated ordered headers used in the signature.
    #[serde(default)]
    pub tl_headers: Option<String>,
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
            tl_version: Some(Cow::Borrowed("2")),
            tl_headers: Some(header_keys),
            jku: jku.map(Cow::Borrowed),
        }
    }
}
