from __future__ import annotations

# std imports
import base64
import json
from enum import Enum
from typing import Dict, Generic, Iterable, Mapping, Optional, Tuple, TypeVar, Union

T = TypeVar('T', bound='TlJwsBase')
P = TypeVar('P', str, Union[str, Mapping[str, str]])


class HttpMethod(str, Enum):
    POST = "POST"
    GET = "GET"
    PATCH = "PATCH"
    PUT = "PUT"
    DELETE = "DELETE"


class TlJwsBase(Generic[P]):
    pkey: P
    http_method: HttpMethod
    path: str
    headers: Dict[str, str]
    body: str

    def __init__(
        self,
        pkey: P,
        http_method: HttpMethod = HttpMethod.POST,
        path: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: str = ""
    ):
        self.pkey = pkey
        self.http_method = http_method
        self.path = path
        self.headers = {} if headers is None else headers
        self.body = body

    def set_method(self: T, http_method: HttpMethod) -> T:
        """
        Add the request method, defaults to `"POST"` if unspecified.
        """
        self.http_method = http_method
        return self

    def set_path(self: T, path: str) -> T:
        """
        Add the request absolute path starting with a leading `/` and without
        any trailing slashes.
        """
        self.path = path
        return self

    def add_headers(self: T, headers: Mapping[str, str]) -> T:
        """
        Appends multiple header names & values.

        Warning: Only a single value per header name is supported.
        """
        for k, v in headers.items():
            self.headers[k] = v
        return self

    def add_header(self: T, header: str, value: str) -> T:
        """
        Add a header name & value.
        May be called multiple times to add multiple different headers.

        Warning: Only a single value per header name is supported.
        """
        self.headers[header] = value
        return self

    def set_body(self: T, body: str) -> T:
        """
        Add the full request body.

        Note: This **must** be identical to what is sent with the request.
        """
        self.body = body
        return self


def build_v2_signing_payload(
    method: str,
    path: str,
    headers: Iterable[Tuple[str, str]],
    body: str
) -> str:
    """
    Build a TLv2 signing payload.
    Retruns signing payload as a string

    ```txt
    POST /test-signature
    Idempotency-Key: 619410b3-b00c-406e-bb1b-2982f97edb8b
    {"bar":123}
    ```
    """
    payload = f"{method} {path}\n"
    for key, value in headers:
        payload += f"{key}: {value}\n"
    payload += body
    return payload


def build_v2_jws_b64(
    jws_header: Mapping[str, str],
    method: str,
    path: str,
    headers: Iterable[Tuple[str, str]],
    body: str
) -> Tuple[bytes, bytes]:
    """
    Build a TLv2 jws.

    Raises:
        - UnicodeEncodeError: If any of the given strings are not unicoded enocded
    """
    # enocde header
    json_header = json.dumps(jws_header, separators=(",", ":")).encode()
    jws_header_b64 = to_url_safe_base64(json_header)

    # build payload
    payload = build_v2_signing_payload(method, path, headers, body)
    payload_b64 = to_url_safe_base64(payload.encode())

    return jws_header_b64, b".".join((jws_header_b64, payload_b64))


def decode_url_safe_base64(input: bytes, zero_pad=0) -> bytes:
    """
    decodes bytes from url safe base64 alphabet without padding
    """
    input += b"=" * (4 - (len(input) % 4))
    output = base64.urlsafe_b64decode(input)
    padding = bytes(bytearray(max(0, zero_pad-len(output))))
    return padding + output


def to_url_safe_base64(input: bytes) -> bytes:
    """
    Encodes bytes into url safe base64 alphabet without padding
    """
    return base64.urlsafe_b64encode(input).replace(b"=", b"")
