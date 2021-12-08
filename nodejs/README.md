# truelayer-signing
Node library supporting JavaScript and TypeScript to produce & verify TrueLayer API requests signatures.

```sh
npm install --save truelayer-signing
# or using yarn
yarn add truelayer-signing
```

### Usage
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

### TypeScript usage
```typescript
import * as tlSigning from 'truelayer-signing';

// `Tl-Signature` value to send with the request.
const signature = tlSigning.sign({
  kid,
  privateKeyPem,
  method: tlSigning.HttpMethod.Post,
  path: "/payouts",
  headers: { "Idempotency-Key": idempotencyKey },
  body,
});
```

## Verifying webhooks
The `verify` function may be used to verify webhook `Tl-Signature` header signatures.
 
```javascript
const tlSigning = require('truelayer-signing');

let jku = tlSigning.extractJku(webhookSignature);

// fetch jwks JSON from the `jku` url.
let jwks = fetch_jwks(jku);

// jwks may be used directly to verify a signature
// a SignatureError is thrown is verification fails
tlSigning.verify({
  jwks,
  signature: webhookSignature,
  method: "post",
  path,
  body,
  headers,
});
```
