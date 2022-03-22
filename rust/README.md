# truelayer-signing
Rust crate to produce & verify TrueLayer API requests signatures.

[![Crates.io](https://img.shields.io/crates/v/truelayer-signing.svg)](https://crates.io/crates/truelayer-signing)
[![Docs.rs](https://docs.rs/truelayer-signing/badge.svg)](https://docs.rs/truelayer-signing)

```rust
// `Tl-Signature` value to send with the request.
let tl_signature = truelayer_signing::sign_with_pem(kid, private_key)
    .method("POST")
    .path("/payouts")
    .header("Idempotency-Key", idempotency_key)
    .body(body)
    .sign()?;
```

## Prerequisites
- OpenSSL (see [here](https://www.openssl.org/) for instructions).

## Verifying webhooks
The `verify_with_jwks` function may be used to verify webhook `Tl-Signature` header signatures.
 
```rust
// `jku` field is included in webhook signatures
let jku = truelayer_signing::extract_jws_header(webhook_signature)?.jku?;

// check `jku` is an allowed TrueLayer url & fetch jwks JSON (not provided by this lib)
ensure_jku_allowed(jku)?;
let jwks = fetch_jwks(jku);

// jwks may be used directly to verify a signature
truelayer_signing::verify_with_jwks(jwks)
    .method("POST")
    .path(path)
    .headers(all_webhook_headers)
    .body(body)
    .verify(webhook_signature)?;
```

See [webhook server example](./examples/webhook-server/).
