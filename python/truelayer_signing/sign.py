from __future__ import annotations

# std imports
from dataclasses import dataclass
from typing import Dict, Mapping, Optional

# third party imports
from jwt.algorithms import ECAlgorithm

# local imports
from .utils import HttpMethod, TlJwsBase, build_v2_jws_b64, to_url_safe_base64


class TlSigner(TlJwsBase):
    """
    Tl-Signer
    """
    kid: str

    def __init__(
        self,
        kid: str,
        pkey: str,
        method: HttpMethod = HttpMethod.POST,
        path: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: str = ""
    ) -> None:
        super().__init__(pkey, method, path, headers, body)
        self.kid = kid

    def sign(self) -> str:
        """
        Produce a JWS `Tl-Signature` v2.
        """
        return tl_sign(SignArguments(
            self.kid,
            self.pkey,
            self.path,
            self.headers,
            self.body,
            self.http_method
        ))


@dataclass(frozen=True)
class SignArguments:
    kid: str
    pkey: str
    path: str
    headers: Mapping[str, str]
    body: str
    method: HttpMethod


def tl_sign(args: SignArguments) -> str:
    # create the TLv2 jws header
    jws_header = {
        "alg": "ES512",
        "kid": args.kid,
        "tl_version": "2",
        "tl_headers": ",".join(args.headers.keys()),
    }

    # create the jws paintext
    jws_header_b64, jws_header_and_payload = build_v2_jws_b64(
        jws_header,
        args.method,
        args.path,
        args.headers.items(),
        args.body
    )

    # sign the jws
    signer = ECAlgorithm(ECAlgorithm.SHA512)
    key = signer.prepare_key(args.pkey)
    jws_signed = signer.sign(jws_header_and_payload, key)
    jws_signed_b64 = to_url_safe_base64(jws_signed)

    # return url safe criptext
    jws_b64 = jws_header_b64 + b".." + jws_signed_b64
    return jws_b64.decode()
