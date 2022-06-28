from copy import copy
import json
import pytest

from truelayer_signing import (
    sign_with_pem,
    verify_with_jwks,
    verify_with_pem,
    extract_jws_header
)
from truelayer_signing.errors import TlSigningException
from truelayer_signing.utils import HttpMethod


def read_file(path: str) -> str:
    with open(path) as fp:
        return fp.read().strip()


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

    verify_with_pem(PUBLIC_KEY) \
        .set_path(path) \
        .add_header("Idempotency-Key", idempotency_key) \
        .add_required_header("Idempotency-Key") \
        .set_body(body) \
        .verify(signature)


def test_verify_full_request_static_signature():
    body = '{"currency":"GBP","max_amount_in_minor":5000000}'
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"
    tl_signature = read_file("../test-resources/tl-signature.txt").rstrip()

    verify_with_pem(PUBLIC_KEY) \
        .set_method(HttpMethod.POST) \
        .set_path(path) \
        .add_header("X-Whatever-2", "t2345d") \
        .add_header("Idempotency-Key", idempotency_key) \
        .set_body(body) \
        .verify(tl_signature)


def test_mismatched_signature_with_attached_valid_body():
    # signature for `/bar` but with a valid jws-body pre-attached
    # if we run a simple jws verify on this unchanged it'll work!
    tl_signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND\
      ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV\
      hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD\
      z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC\
      QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB\
      d2d3D17Wd9UA"

    with pytest.raises(TlSigningException):
        verify_with_pem(PUBLIC_KEY) \
            .set_method(HttpMethod.POST) \
            .set_path("/foo") \
            .set_body("{}") \
            .verify(tl_signature)


def test_mismatched_signature_with_attached_valid_body_trailing_dots():
    # signature for `/bar` but with a valid jws-body pre-attached
    # if we run a simple jws verify on this unchanged it'll work!
    tl_signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND\
      ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV\
      hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD\
      z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC\
      QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB\
      d2d3D17Wd9UA...."

    with pytest.raises(TlSigningException):
        verify_with_pem(PUBLIC_KEY) \
            .set_method(HttpMethod.POST) \
            .set_path("/foo") \
            .set_body("{}") \
            .verify(tl_signature)


def test_signature_no_headers():
    body = '{"currency":"GBP","max_amount_in_minor":5000000}'
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    signature = sign_with_pem(KID, PRIVATE_KEY) \
        .set_path(path) \
        .set_body(body) \
        .sign()

    verify_with_pem(PUBLIC_KEY) \
        .set_path(path) \
        .set_body(body) \
        .add_header("X-Whatever", "aoitbeh") \
        .verify(signature)


def test_signature_method_mismatch():
    body = '{"currency":"GBP","max_amount_in_minor":5000000}'
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = sign_with_pem(KID, PRIVATE_KEY) \
        .set_method(HttpMethod.POST) \
        .set_path(path) \
        .add_header("Idempotency-Key", idempotency_key) \
        .set_body(body) \
        .sign()

    with pytest.raises(TlSigningException):
        verify_with_pem(PUBLIC_KEY) \
            .set_method(HttpMethod.DELETE) \
            .set_path(path) \
            .add_header("X-Whatever", "aoitbeh") \
            .add_header("Idempotency-Key", idempotency_key) \
            .set_body(body) \
            .verify(tl_signature)


def test_signature_path_mismatch():
    body = '{"currency":"GBP","max_amount_in_minor":5000000}'
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = sign_with_pem(KID, PRIVATE_KEY) \
        .set_method(HttpMethod.POST) \
        .set_path(path) \
        .add_header("Idempotency-Key", idempotency_key) \
        .set_body(body) \
        .sign()

    with pytest.raises(TlSigningException):
        verify_with_pem(PUBLIC_KEY) \
            .set_method(HttpMethod.POST) \
            .set_path("/merchant_accounts/67b5b1cf-1d0c-45d4-a2ea-61bdc044327c/sweeping") \
            .add_header("X-Whatever", "aoitbeh") \
            .add_header("Idempotency-Key", idempotency_key) \
            .set_body(body) \
            .verify(tl_signature)


def test_signature_header_mismatch():
    body = '{"currency":"GBP","max_amount_in_minor":5000000}'
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = sign_with_pem(KID, PRIVATE_KEY) \
        .set_method(HttpMethod.POST) \
        .set_path(path) \
        .add_header("Idempotency-Key", idempotency_key) \
        .set_body(body) \
        .sign()

    with pytest.raises(TlSigningException):
        verify_with_pem(PUBLIC_KEY) \
            .set_method(HttpMethod.POST) \
            .set_path(path) \
            .add_header("X-Whatever", "aoitbeh") \
            .add_header("Idempotency-Key", "something-else") \
            .set_body(body) \
            .verify(tl_signature)


def test_signature_body_mismatch():
    body = '{"currency":"GBP","max_amount_in_minor":5000000}'
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    signature = sign_with_pem(KID, PRIVATE_KEY) \
        .set_path(path) \
        .add_header("Idempotency-Key", idempotency_key) \
        .set_body(body) \
        .sign()

    verify_with_pem(PUBLIC_KEY) \
        .set_path(path) \
        .add_header("Idempotency-Key", idempotency_key) \
        .set_body(body) \
        .verify(signature)


def test_signature_missing_signature_header():
    body = '{"currency":"GBP","max_amount_in_minor":5000000}'
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = sign_with_pem(KID, PRIVATE_KEY) \
        .set_method(HttpMethod.POST) \
        .set_path(path) \
        .add_header("Idempotency-Key", idempotency_key) \
        .set_body(body) \
        .sign()

    with pytest.raises(TlSigningException):
        verify_with_pem(PUBLIC_KEY) \
            .set_method(HttpMethod.POST) \
            .set_path(path) \
            .add_header("X-Whatever", "aoitbeh") \
            .set_body(body) \
            .verify(tl_signature)


def test_signature_required_header_missing_from_signature():
    body = '{"currency":"GBP","max_amount_in_minor":5000000}'
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = sign_with_pem(KID, PRIVATE_KEY) \
        .set_method("post") \
        .set_path(path) \
        .add_header("Idempotency-Key", idempotency_key) \
        .set_body(body) \
        .sign()

    with pytest.raises(TlSigningException):
        verify_with_pem(PUBLIC_KEY) \
            .set_method("post") \
            .set_path(path) \
            .add_required_header("X-Required") \
            .add_header("Idempotency-Key", idempotency_key) \
            .set_body(body) \
            .verify(tl_signature)


def test_flexible_header_case_order_verify():
    body = '{"currency":"GBP","max_amount_in_minor":5000000}'
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = sign_with_pem(KID, PRIVATE_KEY) \
        .set_method("post") \
        .set_path(path) \
        .add_header("Idempotency-Key", idempotency_key) \
        .add_header("X-Custom", "123") \
        .set_body(body) \
        .sign()

    verify_with_pem(PUBLIC_KEY) \
        .set_method("post") \
        .set_path(path) \
        .add_header("X-CUSTOM", "123") \
        .add_header("idempotency-key", idempotency_key) \
        .set_body(body) \
        .verify(tl_signature)


def test_extract_jws_header():
    hook_signature = read_file("../test-resources/webhook-signature.txt")
    jws_header = extract_jws_header(hook_signature)
    assert(jws_header["alg"] == "ES512")
    assert(jws_header["alg"] == "ES512")
    assert(jws_header["kid"] == KID)
    assert(jws_header["tl_version"] == "2")
    assert(jws_header["tl_headers"] == "X-Tl-Webhook-Timestamp,Content-Type")
    assert(jws_header["jku"] ==
           "https://webhooks.truelayer.com/.well-known/jwks")


def test_verify_with_jwks():
    hook_signature = read_file("../test-resources/webhook-signature.txt")
    jwks = json.loads(read_file("../test-resources/jwks.json"))
    jwk = next(filter(lambda x: x["kty"] == "EC", jwks["keys"]))

    verify_with_jwks(copy(jwk)) \
        .set_method("POST") \
        .set_path("/tl-webhook") \
        .add_header("x-tl-webhook-timestamp", "2021-11-29T11:42:55Z") \
        .add_header("content-type", "application/json") \
        .set_body('{"event_type":"example","event_id":"18b2842b-a57b-4887-a0a6-d3c7c36f1020"}') \
        .verify(hook_signature)

    with pytest.raises(TlSigningException):
        verify_with_jwks(jwk) \
            .set_method("POST") \
            .set_path("/tl-webhook") \
            .add_header("x-tl-webhook-timestamp", "2021-12-29T11:42:55Z") \
            .add_header("content-type", "application/json") \
            .set_body('{"event_type":"example","event_id":"18b2842b-a57b-4887-a0a6-d3c7c36f1020"}') \
            .verify(hook_signature)
