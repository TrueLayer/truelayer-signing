# truelayer-signing
Node library supporting JavaScript and TypeScript to produce & verify TrueLayer API requests signatures.

```sh
npm install --save truelayer-signing
# or using yarn
yarn add truelayer-signing
```

## Usage
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

## TypeScript usage
```typescript
import tlSigning from 'truelayer-signing';

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
