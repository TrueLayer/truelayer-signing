const tlSigning = require("truelayer-signing");
const { randomUUID } = require("crypto");
const axios = require('axios');

// Read required env vars
const accessToken = process.env.ACCESS_TOKEN;
if (!accessToken) throw new Error("Missing env var ACCESS_TOKEN");
const kid = process.env.KID;
if (!kid) throw new Error("Missing env var KID");
const privateKeyPem = process.env.PRIVATE_KEY;
if (!privateKeyPem) throw new Error("Missing env var PRIVATE_KEY");

// A random body string is enough for this request as `/test-signature` endpoint does not 
// require any schema, it simply checks the signature is valid against what's received.
const body = `body-${Math.random()}`;
const idempotencyKey = randomUUID();
const tlSignature = tlSigning.sign({
  kid,
  privateKeyPem,
  method: "POST", // as we're sending a POST request
  path: "/test-signature", // the path of our request
  // Optional: /test-signature does not require any headers, but we may sign some anyway.
  // All signed headers *must* be included unmodified in the request.
  headers: {
    "Idempotency-Key": idempotencyKey,
    "X-Bar-Header": "abcdefg",
  },
  body,
});

const request = {
  method: "POST",
  url: "https://api.truelayer-sandbox.com/test-signature",
  // Request body & any signed headers *must* exactly match what was used to generate the signature.
  data: body,
  headers: {
    "Authorization": `Bearer ${accessToken}`,
    "Idempotency-Key": idempotencyKey,
    "X-Bar-Header": "abcdefg",
    "Tl-Signature": tlSignature,
  }
};
console.log("Sending " + JSON.stringify(request, null, 2) + "\n");

axios(request)
  // 204 means success
  .then(response => console.log(`${response.status} ✓`))
  // 401 means either the access token is invalid, or the signature is invalid.
  .catch(err => console.warn(`${err.response.status} ${JSON.stringify(err.response.data)}`));
