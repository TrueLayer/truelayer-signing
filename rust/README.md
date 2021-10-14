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
