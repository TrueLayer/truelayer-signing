# std imports
from copy import copy
from typing import Mapping, List

# local imports
from .errors import TlSigningException
from .sign import TlSigner
from .utils import HttpMethod, JwsHeader
from .verify import KeyFmt, TlVerifier, extract_jws_header


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


def verify_with_jwks(
    jwks: Mapping[str, List[Mapping[str, str]]], jws_header: JwsHeader
) -> TlVerifier:
    """
    Start building a `Tl-Signature` verifier using public key jkws data.
    """
    try:
        pkey = copy(next(filter(lambda x: x["kid"] == jws_header.kid, jwks["keys"])))
    except StopIteration:
        raise TlSigningException("no jwk found for signature kid")
    return TlVerifier(pkey, KeyFmt.JWKS)


__all__ = [
    "HttpMethod",
    "JwsHeader",
    "extract_jws_header",
    "sign_with_pem",
    "verify_with_pem",
    "verify_with_jwks",
]
