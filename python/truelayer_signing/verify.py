from __future__ import annotations

# std imports
import json
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Mapping, Optional, Tuple
from jwt import InvalidKeyError
from json import JSONDecodeError

# third party imports
from jwt.algorithms import ECAlgorithm

# local imports
from .utils import HttpMethod, TlJwsBase, build_v2_jws_b64, decode_url_safe_base64
from .errors import TlSigningException


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

        Raises:
            TlSigningException
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


def tl_verify(args: VerifyArguments):
    """
    Verify the given `Tl-Signature`.

    Raises:
        TlSigningException
    """
    try:
        (jws_header, signature) = _parse_tl_signature(args.tl_signature)
    except (UnicodeDecodeError, UnicodeEncodeError, JSONDecodeError):
        raise TlSigningException("Failed To Decode Signature")
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
        raise TlSigningException(
            f"Missing Required Header Value: {header_name}")

    # build the jws paintext
    _, jws_b64 = build_v2_jws_b64(
        jws_header,
        args.method,
        args.path,
        ordered_headers.items(),
        args.body
    )

    # verify the signature
    verifier = ECAlgorithm(ECAlgorithm.SHA512)
    try:
        if args.key_fmt == KeyFmt.PEM:
            key = verifier.prepare_key(args.pkey)
        elif args.key_fmt == KeyFmt.JWKS:
            key = verifier.from_jwk(args.pkey)
    except (ValueError, InvalidKeyError):
        raise TlSigningException("Invalid Key")

    if not verifier.verify(jws_b64, key, signature):
        raise TlSigningException("Invalid Signature")


def extract_jws_header(tl_signature: str) -> Mapping[str, str]:
    """
    Returns the signatures deserialize headers

    Raises: 
        - JSONDecodeError
        - UnicodeEncodeError
        - UnicodeDecodeError
        - 
    """
    header, _ = tl_signature.split("..")
    header_b64 = header.encode()
    headers = json.loads(decode_url_safe_base64(header_b64).decode())
    _verify_header(headers)
    return headers


def _parse_tl_signature(tl_signature: str) -> Tuple[Mapping[str, str], bytes]:
    """
    Returns deserialize headers and decoded payload.

    Raises:
        - JSONDecodeError
        - UnicodeEncodeError
        - UnicodeDecodeError
    """
    header, signature = tl_signature.split("..")

    # decode header
    header_b64 = header.encode()
    headers = json.loads(decode_url_safe_base64(header_b64).decode())

    # decode signature
    signature_b64 = signature.encode()
    raw_signature = decode_url_safe_base64(signature_b64)

    return (headers, raw_signature)


def _verify_header(header: Mapping[str, str]):
    """
    Verify the JWT header.

    Raises:
        - TlSigningException
    """
    if any(x not in header.keys() for x in ["alg", "kid", "tl_version", "tl_headers"]):
        raise TlSigningException("Invaild Header")

    if header["alg"] != "ES512":
        raise TlSigningException("Unexpected Header Algorithm")

    if header["tl_version"] != "2":
        raise TlSigningException("Expected tl_version 2")
