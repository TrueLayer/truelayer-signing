# truelayer-signing

## Description

Python package to produce & verify TrueLayer API requests signatures.

## How to build

Python: `poetry install`

## Contributing
Enable `black` and `flake-8` pre-commit hooks: `pre-commit install`

## How to test
- Type checking: `poetry run mypy ./truelayer_signing`

- Test suite: `poetry run pytest -v tests/`


```
tl_signature = sign_with_pem(KID, PRIVATE_KEY) \
    .set_method(HttpMethod.POST) \
    .set_path(path) \
    .add_header("Idempotency-Key", idempotency_key) \
    .set_body(body) \
    .sign()
```
See [full example](./examples/sign-request/).

## Verifying webhooks
The `verify_with_jwks` function may be used to verify webhook `Tl-Signature` header signatures.

```
# `jku` field is included in webhook signatures
let jws_header = extract_jws_header(webhook_signature)["jku"]

// check `jku` is an allowed TrueLayer url & fetch jwks JSON (not provided by this lib)
ensure_jku_allowed(jku)
jwks = fetch_jwks(jku)

// jwks may be used directly to verify a signature
verify_with_jwks(jwks, jws_header) \
    .set_method(HttpMethod.POST) \
    .set_path(path) \
    .add_headers(headers) \
    .set_body(body) \
    .verify(tl_signature)
```

See [webhook server example](./examples/webhook-server/).
