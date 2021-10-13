# truelayer-request-signature
Rust crate to produce & verify TrueLayer API requests signatures.

[![Crates.io](https://img.shields.io/crates/v/truelayer-request-signature.svg)](https://crates.io/crates/truelayer-request-signature)
[![Docs.rs](https://docs.rs/truelayer-request-signature/badge.svg)](https://docs.rs/truelayer-request-signature)

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
