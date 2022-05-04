from __future__ import annotations

# std imports
import json
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Mapping, Optional, Tuple

# third party imports
from jwt.algorithms import ECAlgorithm

# local imports
from .utils import HttpMethod, TlJwsBase, build_v2_jws_b64, decode_url_safe_base64


class KeyFmt(Enum):
    PEM = 0
    JWKS = 1


class TlVerifier(TlJwsBase):
    """
    Tl-Verifier
    """
    key_fmt: KeyFmt

    def __init__(
        self,
        pkey: str,
        key_fmt: KeyFmt,
        method: HttpMethod = HttpMethod.POST,
        path: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: str = ""
    ) -> None:
        super().__init__(pkey, method, path, headers, body)
        self.key_fmt = key_fmt

    def verify(self, tl_signature: str) -> bool:
        """
        Verify the given `Tl-Signature`.
        """
        return tl_verify(VerifyArguments(
            tl_signature,
            self.pkey,
            self.key_fmt,
            self.path,
            self.headers,
            self.body,
            self.http_method
        ))


@dataclass(frozen=True)
class VerifyArguments:
    tl_signature: str
    pkey: str
    key_fmt: KeyFmt
    path: str
    headers: Mapping[str, str]
    body: str
    method: HttpMethod


def tl_verify(args: VerifyArguments) -> bool:
    (jws_header, signature) = _parse_tl_signature(args.tl_signature)
    _verify_header(jws_header)

    # order headers
    try:
        header_names = jws_header["tl_headers"].split(',')
        ordered_headers = OrderedDict()
        for header_name in header_names:
            key = next(filter(
                lambda x: x.lower() == header_name.lower(),
                args.headers.keys()
            ))
            ordered_headers[header_name] = args.headers[key]
    except StopIteration:
        raise ValueError(f"Missing Required Header Value: {header_name}")

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
    if args.key_fmt == KeyFmt.PEM:
        key = verifier.prepare_key(args.pkey)
    elif args.key_fmt == KeyFmt.JWKS:
        key = verifier.from_jwk(args.pkey)
    else:
        raise ValueError("Undefined Key Format given")
    return verifier.verify(jws_b64, key, signature)


def extract_jws_header(tl_signature: str) -> Mapping[str, str]:
    header, _ = tl_signature.split("..")
    header_b64 = header.encode()
    headers = json.loads(decode_url_safe_base64(header_b64).decode())
    _verify_header(headers)
    return headers


def _parse_tl_signature(tl_signature: str) -> Tuple[Mapping[str, str], bytes]:
    header, signature = tl_signature.split("..")

    # decode header
    header_b64 = header.encode()
    headers = json.loads(decode_url_safe_base64(header_b64).decode())

    # decode signature
    signature_b64 = signature.encode()
    raw_signature = decode_url_safe_base64(signature_b64)

    return (headers, raw_signature)


def _verify_header(header: Mapping[str, str]):
    if any(x not in header.keys() for x in ["alg", "kid", "tl_version", "tl_headers"]):
        raise ValueError("Invaild Header")

    if header["alg"] != "ES512":
        raise ValueError("Unexpected Header Algorithm")

    if header["tl_version"] != "2":
        raise ValueError("Expected tl_version 2")
