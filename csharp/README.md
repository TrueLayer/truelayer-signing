# TrueLayer.Signing
C# library to produce & verify TrueLayer API requests signatures.

[![Nuget](https://img.shields.io/nuget/v/TrueLayer.Signing)](https://www.nuget.org/packages/TrueLayer.Signing)

```csharp
using TrueLayer.Signing;

// `Tl-Signature` value to send with the request.
var tlSignature = Signer.SignWithPem(kid, privateKey)
    .Method("POST")
    .Path(path)
    .Header("Idempotency-Key", idempotency_key)
    .Body(body)
    .Sign();
```

## Verifying webhooks
The `VerifyWithJwks` function may be used to verify webhook `Tl-Signature` header signatures.
 
```csharp
// `jku` field is included in webhook signatures
var jku = Verifier.ExtractJku(webhookSignature);

// fetch jwks JSON from the `jku` url (not provided by this lib)
var jwks = fetchJwks(jku);

// jwks may be used directly to verify a signature
// a SignatureException is thrown is verification fails
Verifier.VerifyWithJwks(jwks)
    .Method("POST")
    .Path(path)
    .Headers(allWebhookHeaders)
    .Body(body)
    .Verify(webhookSignature);
```
