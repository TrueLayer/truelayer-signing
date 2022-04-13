from __future__ import annotations

# std imports
import json
from dataclasses import dataclass
from typing import Dict, Mapping, Tuple

# third party imports
from jwt.algorithms import ECAlgorithm

# local imports
from .utils import HttpMethod, TlJwsBase, build_v2_jws_b64, decode_url_safe_base64


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
            self.http_method
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

    # order headers
    ordered_headers = {k: args.headers[k]
                       for k in jws_header["tl_headers"].split(',')}

    # build the jws paintext
    _, jws_b64 = build_v2_jws_b64(
        jws_header,
        args.method,
        args.path,
        ordered_headers,
        args.body
    )

    # verify the signature
    verifier = ECAlgorithm(ECAlgorithm.SHA512)
    key = verifier.prepare_key(args.pkey)
    return verifier.verify(jws_b64, key, signature)


def _parse_tl_signature(tl_signature: str) -> Tuple[Dict[str, str], bytes]:
    header_b64, signature_b64 = tl_signature.split("..")

    # decode header
    header_b64 = header_b64.encode()
    headers = json.loads(decode_url_safe_base64(header_b64).decode())

    # decode signature
    signature_b64 = signature_b64.encode()
    signature = decode_url_safe_base64(signature_b64)

    return (headers, signature)


def _verify_header(header: Mapping[str, str]):
    if any(x not in header.keys() for x in ["alg", "kid", "tl_version", "tl_headers"]):
        raise ValueError("Invaild header")

    if header["alg"] != "ES512":
        raise ValueError("unexpected header alg")

    if header["tl_version"] != "2":
        raise ValueError("expected tl_version 2")
