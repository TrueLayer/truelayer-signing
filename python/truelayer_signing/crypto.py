from __future__ import annotations

# std imports
import binascii
import json
from typing import Mapping, Optional, Union

# third party imports
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

# local imports
from .errors import INVALID_SIGNATURE, UNSUPPORTED_ALGORITHM, TlSigningException
from .utils import decode_url_safe_base64


class Ec512:
    inner: Union[Ec512Pivate, Ec512Public]

    def __init__(self, inner: Union[Ec512Pivate, Ec512Public]) -> None:
        self.inner = inner

    @classmethod
    def load_from_jwks(cls, jwks: Union[str, Mapping[str, str]]) -> "Ec512":
        # adds zero-padding to keys
        if isinstance(jwks, str):
            pkey = json.loads(jwks)
        elif isinstance(jwks, Mapping):
            pkey = jwks
        else:
            raise ValueError

        x = decode_url_safe_base64(pkey["x"].encode(), zero_pad=66)
        y = decode_url_safe_base64(pkey["y"].encode(), zero_pad=66)

        if not len(x) == len(y) == 66:
            raise TlSigningException("Coords should be 66 bytes for curve P-521")

        if pkey["crv"] != "P-521":
            curve = pkey["crv"]
            raise TlSigningException(f"Requires P-521 curve, found {curve}")

        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x, byteorder="big"),
            y=int.from_bytes(y, byteorder="big"),
            curve=ec.SECP521R1(),
        )

        if "d" not in pkey:
            return cls(Ec512Public(public_numbers.public_key()))

        d = decode_url_safe_base64(pkey["d"].encode(), zero_pad=66)

        if not len(d) == 66:
            raise TlSigningException("Coords should be 66 bytes for curve P-521")

        return cls(
            Ec512Pivate(
                ec.EllipticCurvePrivateNumbers(
                    int.from_bytes(d, byteorder="big"), public_numbers
                ).private_key()
            )
        )

    @classmethod
    def load_from_pem(cls, pem: bytes, password: Optional[bytes] = None) -> "Ec512":
        # try and load the pem as a public key first if a value error is raised
        # ignore it and try loading the pem as a private key
        try:
            pub_inner = Ec512Public.load_pem_public_key(pem)
            return cls(pub_inner)
        except ValueError:
            pass

        try:
            priv_inner = Ec512Pivate.load_pem_private_key(pem, password)
            return cls(priv_inner)
        except ValueError:
            raise TlSigningException("PEM could not be decoded successfully")
        except TypeError:
            raise TlSigningException("Password provided when PEM was not encrypted")

    def to_public(self) -> None:
        if isinstance(self.inner, Ec512Pivate):
            self.inner = self.inner.public_key

    def sign(self, data: bytes) -> bytes:
        if isinstance(self.inner, Ec512Pivate):
            return self.inner.sign(data)
        else:
            raise TlSigningException("Signing requires a private key")

    def verify(self, signature: bytes, data: bytes) -> None:
        self.inner.verify(signature, data)


class Ec512Public:
    public_key: ec.EllipticCurvePublicKey

    def __init__(self, public_key: ec.EllipticCurvePublicKey) -> None:
        self.public_key = public_key

    @classmethod
    def load_pem_public_key(cls, pem: bytes) -> "Ec512Public":
        try:
            # will raise ValueError, or UnsupportedAlgorithm
            public_key = load_pem_public_key(pem)
        except UnsupportedAlgorithm:
            raise TlSigningException(UNSUPPORTED_ALGORITHM)

        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return cls(public_key)
        else:
            raise TlSigningException(UNSUPPORTED_ALGORITHM)

    def verify(self, signature: bytes, msg: bytes) -> None:
        num_bits = self.public_key.curve.key_size
        num_bytes = (num_bits + 7) // 8

        if len(signature) != 2 * num_bytes:
            raise TlSigningException(INVALID_SIGNATURE)

        try:
            r = bytes_to_number(signature[:num_bytes])
            s = bytes_to_number(signature[num_bytes:])
            der_sig = encode_dss_signature(r, s)
            self.public_key.verify(der_sig, msg, ec.ECDSA(hashes.SHA512()))
        except InvalidSignature:
            raise TlSigningException(INVALID_SIGNATURE)


class Ec512Pivate:
    private_key: ec.EllipticCurvePrivateKey
    public_key: Ec512Public

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self.private_key = private_key
        self.public_key = Ec512Public(private_key.public_key())

    @classmethod
    def load_pem_private_key(
        cls, pem: bytes, password: Optional[bytes] = None
    ) -> "Ec512Pivate":
        try:
            # will raise ValueError, TypeError, or UnsupportedAlgorithm
            private_key = load_pem_private_key(pem, password)
        except UnsupportedAlgorithm:
            raise TlSigningException(UNSUPPORTED_ALGORITHM)

        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            return cls(private_key)
        else:
            raise TlSigningException(UNSUPPORTED_ALGORITHM)

    def sign(self, data: bytes) -> bytes:
        der_sig = self.private_key.sign(data, ec.ECDSA(hashes.SHA512()))

        r, s = decode_dss_signature(der_sig)
        num_bits = self.private_key.curve.key_size
        num_bytes = (num_bits + 7) // 8
        return number_to_bytes(r, num_bytes) + number_to_bytes(s, num_bytes)

    def verify(self, signature: bytes, data: bytes) -> None:
        self.public_key.verify(signature, data)


def number_to_bytes(num: int, num_bytes: int) -> bytes:
    padded_hex = "%0*x" % (2 * num_bytes, num)
    return binascii.a2b_hex(padded_hex.encode("ascii"))


def bytes_to_number(string: bytes) -> int:
    return int(binascii.b2a_hex(string), 16)
