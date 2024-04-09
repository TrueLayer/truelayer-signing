use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

pub(crate) trait ToUrlSafeBase64 {
    fn to_url_safe_base64(&self) -> String;
}
impl<S> ToUrlSafeBase64 for S
where
    S: AsRef<[u8]>,
{
    #[inline]
    fn to_url_safe_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self)
    }
}
pub(crate) trait DecodeUrlSafeBase64 {
    fn decode_url_safe_base64(&self) -> Result<Vec<u8>, base64::DecodeError>;
}
impl<S> DecodeUrlSafeBase64 for S
where
    S: AsRef<[u8]>,
{
    #[inline]
    fn decode_url_safe_base64(&self) -> Result<Vec<u8>, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(self)
    }
}
