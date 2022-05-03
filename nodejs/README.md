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

See [full example](./examples/sign-request/).

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

// `jku` field is included in webhook signatures
let jku = tlSigning.extractJku(webhookSignature);

// check `jku` is an allowed TrueLayer url & fetch jwks JSON (not provided by this lib)
ensureJkuAllowed(jku);
let jwks = fetchJwks(jku);

// jwks may be used directly to verify a signature
// a SignatureError is thrown is verification fails
tlSigning.verify({
  jwks,
  signature: webhookSignature,
  method: "post",
  path,
  body,
  headers: allWebhookHeaders,
});
```

See [full example](./examples/webhook-server/).
