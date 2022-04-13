from truelayer_signing import sign_with_pem, verify_with_pem


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
