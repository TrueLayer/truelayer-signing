from __future__ import annotations

# std imports
import json
from typing import Dict, Mapping, Tuple
from dataclasses import dataclass

# third party imports
from cryptography.hazmat.primitives import serialization
from jwt.algorithms import ECAlgorithm

# local imports
from .utils import HttpMethod, TlJwsBase, build_v2_jws_b64, base64url_decode


class TlVerifier(TlJwsBase):
    """
    Tl-Verifier
    """

    def verify(self, tl_signature: str) -> bool:
        """
        Verify the given `Tl-Signature`.
        """
        return tl_verify(VerifyArguments(
            tl_signature,
            self.pkey,
            self.path,
            self.headers,
            self.body,
            self.method
        ))


@dataclass(frozen=True)
class VerifyArguments:
    tl_signature: str
    pkey: str
    path: str
    headers: Mapping[str, str]
    body: str
    method: HttpMethod


def tl_verify(args: VerifyArguments) -> bool:
    (jws_header, signature) = _parse_tl_signature(args.tl_signature)
    _verify_header(jws_header)

    # build the jws paintext
    _, jws_b64 = build_v2_jws_b64(
        jws_header,
        args.method,
        args.path,
        args.headers,
        args.body
    )

    # verify the signature
    key = serialization.load_pem_public_key(args.pkey.encode('utf-8'))
    verifier = ECAlgorithm(ECAlgorithm.SHA512)
    return verifier.verify(jws_b64, key, signature)


def _parse_tl_signature(tl_signature: str) -> Tuple[Dict[str, str], bytes]:
    header_b64, signature_b64 = tl_signature.split("..")

    # decode header
    header_b64 = header_b64.encode('utf-8')
    headers = json.loads(base64url_decode(header_b64).decode("utf-8"))

    # decode signature
    signature_b64 = signature_b64.encode('utf-8')
    signature = base64url_decode(signature_b64)

    return (headers, signature)


def _verify_header(header: Mapping[str, str]):
    if any(x not in header.keys() for x in ["alg", "kid", "tl_version", "tl_headers"]):
        raise ValueError("Invaild header")

    if header["alg"] != "ES512":
        raise ValueError("unexpected header alg")

    if header["tl_version"] != "2":
        raise ValueError("expected tl_version 2")
