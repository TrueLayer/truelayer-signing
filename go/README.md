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

## Installation

Install the package with:

```shell
go get github.com/Truelayer/truelayer-signing/go
```
