import pytest

from truelayer_signing import sign_with_pem, verify_with_pem
from truelayer_signing.utils import HttpMethod


def read_file(path: str) -> str:
    with open(path) as fp:
        return fp.read()


PUBLIC_KEY: str = read_file("../test-resources/ec512-public.pem")
PRIVATE_KEY: str = read_file("../test-resources/ec512-private.pem")
KID: str = "45fc75cf-5649-4134-84b3-192c2c78e990"


def test_tl_sign_and_verify():
    body = '{"currency":"GBP","max_amount_in_minor":5000000}'
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    signature = sign_with_pem(KID, PRIVATE_KEY) \
        .set_path(path) \
        .add_header("Idempotency-Key", idempotency_key) \
        .set_body(body) \
        .sign()

    result = verify_with_pem(PUBLIC_KEY) \
        .set_path(path) \
        .add_header("Idempotency-Key", idempotency_key) \
        .set_body(body) \
        .verify(signature)

    assert(result)


def test_verify_full_request_static_signature():
    body = '{"currency":"GBP","max_amount_in_minor":5000000}'
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"
    tl_signature = read_file("../test-resources/tl-signature.txt").rstrip()

    result = verify_with_pem(PUBLIC_KEY) \
        .set_method(HttpMethod.POST) \
        .set_path(path) \
        .add_header("X-Whatever-2", b"t2345d") \
        .add_header("Idempotency-Key", idempotency_key) \
        .set_body(body) \
        .verify(tl_signature)

    assert(result)


def test_mismatched_signature_with_attached_valid_body():
    # signature for `/bar` but with a valid jws-body pre-attached
    # if we run a simple jws verify on this unchanged it'll work!
    tl_signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND\
      ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV\
      hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD\
      z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC\
      QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB\
      d2d3D17Wd9UA"

    with pytest.raises(Exception):
        verify_with_pem(PUBLIC_KEY) \
            .set_method(HttpMethod.POST) \
            .set_path("/foo") \
            .set_body("{}") \
            .verify(tl_signature)


def mismatched_signature_with_attached_valid_body_trailing_dots():
    # signature for `/bar` but with a valid jws-body pre-attached
    # if we run a simple jws verify on this unchanged it'll work!
    tl_signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND\
      ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV\
      hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD\
      z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC\
      QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB\
      d2d3D17Wd9UA...."

    result = verify_with_pem(PUBLIC_KEY) \
        .set_method("POST") \
        .set_path("/foo") \
        .set_body("{}") \
        .verify(tl_signature)

    assert(not result)
