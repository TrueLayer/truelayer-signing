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

See [full example](./examples/sign-request/).

## Verifying webhooks
The `VerifyWithJwks` function may be used to verify webhook `Tl-Signature` header signatures.
 
```csharp
// `jku` field is included in webhook signatures
var jku = Verifier.ExtractJku(webhookSignature);

// check `jku` is an allowed TrueLayer url & fetch jwks JSON (not provided by this lib)
EnsureJkuAllowed(jku);
var jwks = FetchJwks(jku);

// jwks may be used directly to verify a signature
// a SignatureException is thrown is verification fails
Verifier.VerifyWithJwks(jwks)
    .Method("POST")
    .Path(path)
    .Headers(allWebhookHeaders)
    .Body(body)
    .Verify(webhookSignature);
```

See [webhook server example](./examples/webhook-server/).

## Compatibility
.NET Standard 2.0 is supported however .NET Framework 4.6.x **is not** as it's missing required cryptography libraries. For .NET Framework use 4.7.x or higher.

// TODO: delete me, I'm here just to trigger the pipeline