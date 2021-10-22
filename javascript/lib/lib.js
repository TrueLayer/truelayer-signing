const jws = require('jws');
const { Base64 } = require('js-base64');
const SignatureError = require("./error.js");
const Headers = require("./headers.js");

let requireArg = (arg, name) => {
  if (!arg) throw new Error(`missing argument ${name}`);
  return arg;
};

let buildV2SigningPayload = ({ method, path, headers, body }) => {
  let payload = `${method} ${path}\n`;
  for (let [key, value] of headers.entries) {
    payload += `${key}: ${value}\n`;
  }
  payload += body;
  return payload;
};

const signPayload = ({ privateKeyPem, kid, payload, headerNames }) => {
  try {
    const [header, _, signature] = jws.sign({
      header: {
        alg: 'ES512',
        kid,
        tl_version: "2",
        tl_headers: headerNames.join(","),
      },
      payload,
      privateKey: privateKeyPem,
    }).split('.');

    return `${header}..${signature}`;
  } catch (e) {
    throw new SignatureError(e.message);
  }
};

const parseSignature = (signature) => {
  try {
    const [header, _, footer] = signature.split('.');
    const headerJson = JSON.parse(Base64.decode(header));

    SignatureError.ensure(headerJson.alg === "ES512", "unsupported header alg");
    SignatureError.ensure(headerJson.tl_version === "2", "unsupported header tl_version");

    return {
      headerJson,
      header,
      footer,
    };
  } catch (e) {
    throw new SignatureError(e.message);
  }
}

module.exports = {
  /** Sign/verification error */
  SignatureError: SignatureError,
  /** Produce a JWS `Tl-Signature` v2 header value. */
  sign: (args) => {
    const kid = requireArg(args.kid, "kid");
    const privateKeyPem = requireArg(args.privateKeyPem, "privateKeyPem");
    const method = (args.method || "POST").toUpperCase();
    const path = requireArg(args.path, "path");
    const headers = new Headers(args.headers || {}).validated();
    const body = args.body || "";

    const payload = buildV2SigningPayload({ method, path, headers, body });

    return signPayload({ privateKeyPem, kid, payload, headerNames: headers.names() });
  },
  /** Verify the given `Tl-Signature` header value. */
  verify: (args) => {
    const publicKeyPem = requireArg(args.publicKeyPem, "publicKeyPem");
    const signature = requireArg(args.signature, "signature");
    const method = requireArg(args.method, "method").toUpperCase();
    const path = requireArg(args.path, "path");
    const body = args.body || "";
    const requiredHeaders = args.requiredHeaders || [];
    const headers = new Headers(args.headers || {}).validated();

    const { headerJson, header, footer } = parseSignature(signature);
    const tlHeaders = (headerJson.tl_headers || "").split(",");

    // fail if signature is missing a required header
    for (const required of requiredHeaders) {
      const wasSigned = tlHeaders.some(h => h.toLowerCase() === required.toLowerCase());
      SignatureError.ensure(wasSigned, `signature is missing required header ${required}`);
    }

    headers.retainAndSort(tlHeaders);

    const payload = buildV2SigningPayload({ method, path, headers, body });
    const fullSignature = `${header}.${Base64.encode(payload, true)}.${footer}`;

    if (!jws.verify(fullSignature, headerJson.alg, publicKeyPem)) {
      throw new SignatureError("Invalid signature");
    }
  },
  /** Extract kid from unverified jws Tl-Signature. */
  extractKid: (tlSignature) => parseSignature(tlSignature).headerJson.kid,
};
