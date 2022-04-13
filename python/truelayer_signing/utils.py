from __future__ import annotations

# std imports
import base64
import json
from enum import Enum
from typing import Dict, Mapping, Optional, Tuple, TypeVar

T = TypeVar('T', bound='TlJwsBase')


class HttpMethod(str, Enum):
    POST = "POST"
    GET = "GET"
    PATCH = "PATCH"
    PUT = "PUT"
    DELETE = "DELETE"


class TlJwsBase:
    pkey: str
    method: HttpMethod
    path: str
    headers: Mapping[str, str]
    body: str

    def __init__(
        self,
        pkey: str,
        method: HttpMethod = HttpMethod.POST,
        path: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: str = ""
    ):
        self.pkey = pkey
        self.method = method
        self.path = path
        self.headers = {} if headers is None else headers
        self.body = body

    def set_method(self: T, method: HttpMethod) -> T:
        """
        Add the request method, defaults to `"POST"` if unspecified.
        """
        self.method = method
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
    headers: Mapping[str, str],
    body: str
) -> str:
    """
    Build a TLv2 signing payload.
    Retruns signing payload as a string

    ### Example
    ```txt
    POST /test-signature
    Idempotency-Key: 619410b3-b00c-406e-bb1b-2982f97edb8b
    {"bar":123}
    ```
    """
    payload = f"{method} {path}\n"
    for key, value in headers.items():
        payload += f"{key}: {value}\n"
    payload += body
    return payload


def build_v2_jws_b64(
    jws_header: Mapping[str, str],
    method: str,
    path: str,
    headers: Mapping[str, str],
    body: str
) -> Tuple[bytes, bytes]:
    """
    Build a TLv2 jws.
    """
    # enocde header
    json_header = json.dumps(jws_header, separators=(",", ":")).encode('utf-8')
    jws_header_b64 = base64url_encode(json_header)

    # build payload
    payload = build_v2_signing_payload(method, path, headers, body)
    payload_b64 = base64url_encode(payload.encode('utf-8'))

    return jws_header_b64, b".".join((jws_header_b64, payload_b64))


def base64url_decode(input: bytes) -> bytes:
    """
    decodes bytes from url safe base64 alphabet without padding
    """
    input += b"=" * (4 - (len(input) % 4))
    return base64.urlsafe_b64decode(input)


def base64url_encode(input: bytes) -> bytes:
    """
    Encodes bytes into url safe base64 alphabet without padding
    """
    return base64.urlsafe_b64encode(input).replace(b"=", b"")
