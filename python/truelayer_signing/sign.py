from __future__ import annotations

# std imports
from dataclasses import dataclass
from typing import Dict, Mapping, Optional

# local imports
from .crypto import Ec512
from .errors import TlSigningException
from .utils import (
    SIGNING_ALGORITHM,
    TL_VERSION,
    HttpMethod,
    JwsHeader,
    TlJwsBase,
    build_v2_jws_b64,
    to_url_safe_base64,
)


class TlSigner(TlJwsBase[str, HttpMethod]):
    """
    Tl-Signer
    """

    kid: str
    jws_jku: Optional[str]

    def __init__(
        self,
        kid: str,
        pkey: str,
        method: HttpMethod = HttpMethod.POST,
        path: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        jws_jku: Optional[str] = None,
    ) -> None:
        super().__init__(pkey, method, path, headers, body)
        self.kid = kid
        self.jws_jku = jws_jku

    def set_jku(self, jku: str) -> TlSigner:
        self.jws_jku = jku
        return self

    def sign(self) -> str:
        """
        Produce a JWS `Tl-Signature` v2.

        Raises:
            - TlSigningException
        """
        return tl_sign(
            SignArguments(
                self.kid,
                self.pkey,
                self.path,
                self.headers,
                self.body,
                self.http_method,
                self.jws_jku,
            )
        )


@dataclass(frozen=True)
class SignArguments:
    kid: str
    pkey: str
    path: str
    headers: Mapping[str, str]
    body: str
    method: HttpMethod
    jws_jku: Optional[str]


def tl_sign(args: SignArguments) -> str:
    """
    Produce a JWS `Tl-Signature` v2.

    Raises:
        - TlSigningException
    """
    # create the TLv2 jws header
    jws_header = JwsHeader(
        alg=SIGNING_ALGORITHM,
        kid=args.kid,
        tl_version=TL_VERSION,
        tl_headers=",".join(args.headers.keys()),
        jku=args.jws_jku,
    )

    try:
        # create the jws paintext
        jws_header_b64, jws_header_and_payload = build_v2_jws_b64(
            jws_header, args.method, args.path, args.headers.items(), args.body, False
        )

        # sign the jws
        signer = Ec512.load_from_pem(args.pkey.encode())
        jws_signed = signer.sign(jws_header_and_payload)
        jws_signed_b64 = to_url_safe_base64(jws_signed)

        # return url safe criptext
        jws_b64 = jws_header_b64 + b".." + jws_signed_b64
        return jws_b64.decode()
    except UnicodeDecodeError:
        raise TlSigningException("Signature Error")
    except UnicodeEncodeError:
        raise TlSigningException("Encoding Error")
    except ValueError:
        raise TlSigningException("Invalid Key")
