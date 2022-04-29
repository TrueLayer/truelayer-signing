const tlSigning = require("truelayer-signing");
const axios = require('axios');
const express = require('express');
const app = express();

const allowedJkus = {
  "https://webhooks.truelayer.com/.well-known/jwks": true,
  "https://webhooks.truelayer-sandbox.com/.well-known/jwks": true,
};

// global JWK cache
const cachedJwks = {};
async function get_jwks(sig) {
  let kid = tlSigning.extractKid(sig);
  tlSigning.SignatureError.ensure(kid, `Tl-Signature has missing key id`);

  let jku = tlSigning.extractJku(sig);
  tlSigning.SignatureError.ensure(allowedJkus[jku], `Tl-Signature has invalid jku: ${jku}`);

  // check if we have this KID/JKU pair stored
  let jwks = cachedJwks[jku];
  if (jwks) {
    for (let i = 0; i < jwks.keys.length; i++) {
      if (jwks.keys[i].kid == kid) {
        return jwks;
      }
    }
  }

  // otherwise, fetch the JWKs from the server
  cachedJwks[jku] = (await axios.get(jku)).data;
  return cachedJwks[jku];
}

async function verify_hook(req) {
  // extract the Tl-Signature from the headers
  let sig = req.headers["tl-signature"];
  tlSigning.SignatureError.ensure(sig, "missing Tl-Signature header");

  // get the (cached) JWKs for this request
  let jwks = await get_jwks(sig);

  // verify the request (will throw on failure)
  tlSigning.verify({
    signature: sig,
    method: req.method,
    path: req.path,
    headers: req.headers,
    body: JSON.stringify(req.body),
    jwks: JSON.stringify(jwks),
  });
}

app.post('/hook/:id',
  express.json(), // parse body as json
  (req, res, next) => {
    // attempt to verify the webhook
    // if success, call the next handler
    // if failure, return 403 Forbidden
    return verify_hook(req)
      .then(next)
      .catch(err => {
        console.warn(err);
        res.status(403).end();
      });
  },
  (_req, res) => {
    res.status(202).end();
  }
);

app.listen(3000);
