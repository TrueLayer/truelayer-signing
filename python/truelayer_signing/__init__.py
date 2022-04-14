# local imports
from .sign import TlSigner
from .utils import HttpMethod as HttpMethod
from .verify import TlVerifier, KeyFmt, extract_jws_header as extract_jws_header


def sign_with_pem(kid: str, pkey: str) -> TlSigner:
    """
    Start building a request `TlSignature` value using private key
    pem data & the key's `kid`.
    """
    return TlSigner(kid, pkey)


def verify_with_pem(pkey: str) -> TlVerifier:
    """
    Start building a `Tl-Signature` verifier using public key pem data.
    """
    return TlVerifier(pkey, KeyFmt.PEM)


def verify_with_jkws(jkws: str) -> TlVerifier:
    """
    Start building a `Tl-Signature` verifier using public key jkws data.
    """
    return TlVerifier(jkws, KeyFmt.JWKS)
