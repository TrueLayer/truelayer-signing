# TrueLayer.Signing
C# library to produce & verify TrueLayer API requests signatures.

```xml
<PackageReference Include="TrueLayer.Signing" Version="_" />
```

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
