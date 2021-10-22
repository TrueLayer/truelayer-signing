# truelayer-signing
Javascript library to produce & verify TrueLayer API requests signatures.

```javascript
const tlSigning = require('truelayer-signing');

// `Tl-Signature` value to send with the request.
const signature = tlSigning.sign({
  kid,
  privateKeyPem,
  method: "POST",
  path: "/payouts",
  headers: { "Idempotency-Key": idempotencyKey },
  body,
});
```
