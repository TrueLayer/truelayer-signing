use openssl::{
    bn::BigNum,
    ec::EcKey,
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
};

pub fn parse_ec_private_key(private_key: &[u8]) -> anyhow::Result<EcKey<Private>> {
    let private_key = PKey::private_key_from_pem(private_key)?.ec_key()?;
    private_key.check_key()?;
    anyhow::ensure!(
        private_key.group().curve_name() == Some(Nid::SECP521R1),
        "the underlying elliptic curve must be P-521 to sign using ES512"
    );
    Ok(private_key)
}

pub fn parse_ec_public_key(public_key: &[u8]) -> anyhow::Result<EcKey<Public>> {
    let public_key = PKey::public_key_from_pem(public_key)?.ec_key()?;
    public_key.check_key()?;
    anyhow::ensure!(
        public_key.group().curve_name() == Some(Nid::SECP521R1),
        "the underlying elliptic curve must be P-521 to verify ES512"
    );
    Ok(public_key)
}

/// Sign a payload using the provided private key and return the signature.
///
/// Check section A.4 of RFC7515 for the details <https://www.rfc-editor.org/rfc/rfc7515.txt>
pub fn sign_es512(key: &EcKey<Private>, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let hash = openssl::hash::hash(MessageDigest::sha512(), payload)?;
    let structured_signature = EcdsaSig::sign(&hash, key)?;

    let r = structured_signature.r().to_vec();
    let s = structured_signature.s().to_vec();
    let mut signature_bytes: Vec<u8> = Vec::with_capacity(132);
    // Padding to fixed length
    signature_bytes.extend(std::iter::repeat(0x00).take(66 - r.len()));
    signature_bytes.extend(r);
    // Padding to fixed length
    signature_bytes.extend(std::iter::repeat(0x00).take(66 - s.len()));
    signature_bytes.extend(s);

    Ok(signature_bytes)
}

pub fn verify_es512(key: &EcKey<Public>, payload: &[u8], signature: &[u8]) -> anyhow::Result<()> {
    if signature.len() != 132 {
        return Err(anyhow::anyhow!(
            "the signature for ES512 must be 132 bytes long"
        ));
    }
    let r = BigNum::from_slice(&signature[..66])?;
    let s = BigNum::from_slice(&signature[66..132])?;
    let sig = EcdsaSig::from_private_components(r, s)?;

    let hash = openssl::hash::hash(MessageDigest::sha512(), payload)?;

    if sig.verify(&hash, key)? {
        Ok(())
    } else {
        Err(anyhow::anyhow!("signature validation failed"))
    }
}
