# truelayer-signing

Convenient libraries to produce TrueLayer API requests signatures.

Request signatures are created using a private key and included with certain API requests.
They can then be verified using the associated public key.

* [C#](./csharp)
* [Go](./go)
* [Java](./java)
* [Java 7](./java7)
* [Node.js](./nodejs)
* [PHP](./php)
* [Python](./python)
* [Ruby](./ruby)
* [Rust](./rust)

## Request signing specification

See [request-signing-v2.md](./request-signing-v2.md) for an explanation of how request signing is implemented.

## Webhook signature verification

TrueLayer webhooks include a `Tl-Signature` header similar to request signatures but signed by a TrueLayer private key.
See per-language examples on how to properly verify webhooks.

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
</sub>
