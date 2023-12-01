from __future__ import annotations

# std imports
import json
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, List, Mapping, Optional, Tuple, Union
from json import JSONDecodeError

# local imports
from .crypto import Ec512
from .utils import (
    HttpMethod,
    JwsHeader,
    TlJwsBase,
    build_v2_jws_b64,
    decode_url_safe_base64,
)
from .errors import INVALID_KEY, INVALID_SIGNATURE, TlSigningException


class KeyFmt(Enum):
    PEM = 0
    JWKS = 1


class TlVerifier(TlJwsBase[Union[str, Mapping[str, str]], Optional[HttpMethod]]):
    """
    Tl-Verifier
    """

    key_fmt: KeyFmt
    required_headers: List[str]

    def __init__(
        self,
        pkey: Union[str, Mapping[str, str]],
        key_fmt: KeyFmt,
        method: Optional[HttpMethod] = None,
        path: str = "",
        headers: Optional[Dict[str, str]] = None,
        required_headers: Optional[List[str]] = None,
        body: str = "",
    ) -> None:
        super().__init__(pkey, method, path, headers, body)
        self.key_fmt = key_fmt
        self.required_headers = required_headers if required_headers else []

    def add_required_header(self, header: str) -> TlVerifier:
        self.required_headers.append(header)
        return self

    def add_required_headers(self, headers: Iterable[str]) -> TlVerifier:
        self.required_headers.extend(headers)
        return self

    def verify(self, tl_signature: str) -> None:
        """
        Verify the given `Tl-Signature`.

        Raises:
            TlSigningException
        """
        if self.http_method is None:
            raise TlSigningException("HttpMethod not set")

        tl_verify(
            VerifyArguments(
                tl_signature,
                self.pkey,
                self.key_fmt,
                self.path,
                self.headers,
                self.required_headers,
                self.body,
                self.http_method,
            )
        )


@dataclass(frozen=True)
class VerifyArguments:
    tl_signature: str
    pkey: Union[str, Mapping[str, str]]
    key_fmt: KeyFmt
    path: str
    headers: Mapping[str, str]
    required_headers: Iterable[str]
    body: str
    method: HttpMethod


def tl_verify(args: VerifyArguments) -> None:
    """
    Verify the given `Tl-Signature`.

    Raises:
        TlSigningException
    """
    (jws_header, signature) = _parse_tl_signature(args.tl_signature)

    # order headers
    try:
        header_names = (
            jws_header.tl_headers.split(",") if jws_header.tl_headers != "" else []
        )

        ordered_headers: OrderedDict[str, str] = OrderedDict()
        for header_name in header_names:
            key = next(
                filter(lambda x: x.lower() == header_name.lower(), args.headers.keys())
            )
            ordered_headers[header_name] = args.headers[key]
    except StopIteration:
        raise TlSigningException(f"Missing Required Header Value: {header_name}")

    header_diff = {header.lower() for header in args.required_headers} - {
        header.lower() for header in ordered_headers.keys()
    }
    if header_diff:
        missing_headers = " ".join(header_diff)
        raise TlSigningException(f"Missing Required Header(s): {missing_headers}")

    # build the jws plaintext
    try:
        _, jws_b64 = build_v2_jws_b64(
            jws_header,
            args.method,
            args.path,
            ordered_headers.items(),
            args.body,
            False,
        )
    except UnicodeEncodeError:
        raise TlSigningException("Internal Error")

    # verify the signature
    if args.key_fmt == KeyFmt.PEM and isinstance(args.pkey, str):
        verifier = Ec512.load_from_pem(args.pkey.encode())
    elif args.key_fmt == KeyFmt.JWKS:
        verifier = Ec512.load_from_jwks(args.pkey)
    else:
        raise TlSigningException(INVALID_KEY)

    try:
        verifier.verify(signature, jws_b64)
    except TlSigningException:
        (path, slash) = (
            (args.path[:-1], False) if args.path.endswith("/") else (args.path, True)
        )
        _, jws_b64_2 = build_v2_jws_b64(
            jws_header,
            args.method,
            path,
            ordered_headers.items(),
            args.body,
            slash,
        )
        verifier.verify(signature, jws_b64_2)


def extract_jws_header(tl_signature: str) -> JwsHeader:
    """
    Returns the signatures deserialize headers

    Raises:
        - TlSigningException
    """
    try:
        (header, _) = signature_split(tl_signature)
        header_b64 = header.encode()
        headers: Mapping[str, str] = json.loads(
            decode_url_safe_base64(header_b64).decode()
        )
        return JwsHeader.from_dict(headers)
    except (UnicodeDecodeError, UnicodeEncodeError, JSONDecodeError) as e:
        raise TlSigningException(f"Failed to parse JWS: {e}", e)


def _parse_tl_signature(tl_signature: str) -> Tuple[JwsHeader, bytes]:
    """
    Returns deserialize headers and decoded payload.

    Raises:
        - TlSigningException
    """
    headers = extract_jws_header(tl_signature)

    # decode signature
    try:
        (_, signature) = signature_split(tl_signature)
        signature_b64 = signature.encode()
        raw_signature = decode_url_safe_base64(signature_b64)
    except (UnicodeDecodeError, UnicodeEncodeError) as e:
        raise TlSigningException(f"signature decode failed: {e}")

    return (headers, raw_signature)


def signature_split(tl_signature: str) -> Tuple[str, str]:
    try:
        header, signature = tl_signature.split("..", maxsplit=1)
        return (header, signature)
    except ValueError:
        raise TlSigningException(INVALID_SIGNATURE)
