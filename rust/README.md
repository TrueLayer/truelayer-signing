# truelayer-request-signature
Rust crate to produce & verify TrueLayer API requests signatures.

```rust
// `Tl-Signature` value to send with the request.
let tl_signature = truelayer_request_signature::sign_with_pem(kid, private_key)
    .method("POST")
    .path("/payouts")
    .header("Idempotency-Key", idempotency_key)
    .body(body)
    .sign()?;
```

## Prerequisites
- OpenSSL (see [here](https://www.openssl.org/) for instructions).
