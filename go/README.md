# truelayer-signing
Go package to produce & verify TrueLayer API requests signatures.

```go
// `Tl-Signature` value to send with the request.
signature, err := tlsigning.SignWithPem(Kid, privateKeyBytes).
        Method("POST").
        Path("/payouts").
        Header("Idempotency-Key", idempotencyKey).
        Body(body).
        Sign()
```

## Verifying webhooks
The `VerifyWithJwks` function can be used to verify webhook `Tl-Signature` header signatures.

```go
// `jku` field is included in webhook signatures
jku := tlsigning.ExtractJwsHeader(webhookSignature).Jku

// fetch jwks JSON from the `jku` url (not provided by this lib)
jwks := fetchJwks(jku)

// jwks may be used directly to verify a signature
err := tlsigning.VerifyWithJwks(jwks).
        Method("POST").
        Path(path).
        Headers(allWebhookHeaders).
        Body(body).
        Verify(webhookSignature)
```

## Installation

Install the package with:

```shell
go get github.com/Truelayer/truelayer-signing/go
```
