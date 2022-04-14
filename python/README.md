# truelayer-signing
Python package to produce & verify TrueLayer API requests signatures.

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
let jku = extract_jws_header(webhook_signature)["jku"];

// check `jku` is an allowed TrueLayer url & fetch jwks JSON (not provided by this lib)
ensure_jku_allowed(jku)?;
jwks = fetch_jwks(jku);

// jwks may be used directly to verify a signature
res = verify_with_jwks(jwks) \
    .set_method(HttpMethod.POST) \
    .set_path(path) \
    .add_headers(all_webhook_headers) \
    .set_body(body) \
    .verify(webhook_signature)

assert(res)
```

See [webhook server example](./examples/webhook-server/).
