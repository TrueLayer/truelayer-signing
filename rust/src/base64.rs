pub(crate) trait ToUrlSafeBase64 {
    fn to_url_safe_base64(&self) -> String;
}
impl<S> ToUrlSafeBase64 for S
where
    S: AsRef<[u8]>,
{
    #[inline]
    fn to_url_safe_base64(&self) -> String {
        base64::encode_config(self, base64::URL_SAFE_NO_PAD)
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
        base64::decode_config(self, base64::URL_SAFE_NO_PAD)
    }
}
