# truelayer-signing
Python package to produce & verify TrueLayer API requests signatures.

```
tl_signature = sign_with_pem(KID, PRIVATE_KEY) \
    .set_path(path) \
    .add_header("Idempotency-Key", idempotency_key) \
    .set_body(body) \
    .sign()
```
