import jws from "jws";
import jwkToPem from "jwk-to-pem";
import { Base64 } from "js-base64";
import { SignatureError } from "./error";
import { Headers } from "./headers";

const requireArg = <R>(arg: R | undefined, name: string): R => {
  if (!arg) throw new Error(`missing argument ${name}`);
  return arg;
};

const hasMessage = (e: unknown): e is { message: string } => {
  return typeof e === "object" && e !== null && "message" in e;
};

export const enum HttpMethod {
  Post = "POST",
  Get = "GET",
  Patch = "PATCH",
  Put = "PUT",
  Delete = "DELETE",
}

type BuildSigningPayloadConfig = {
  method: HttpMethod;
  path: string;
  headers: Headers;
  body: string;
};

const buildV2SigningPayload = ({
  method,
  path,
  headers,
  body,
}: BuildSigningPayloadConfig) => {
  let payload = `${method} ${path}\n`;

  for (const [key, value] of headers.entries) {
    payload += `${key}: ${value}\n`;
  }

  payload += body;
  return payload;
};

type SignPayloadConfig = {
  privateKeyPem: string;
  kid: string;
  payload: string;
  headerNames: string[];
};

const signPayload = ({
  privateKeyPem,
  kid,
  payload,
  headerNames,
}: SignPayloadConfig) => {
  try {
    const [header, _, signature] = jws
      .sign({
        header: {
          alg: "ES512",
          kid,
          tl_version: "2",
          tl_headers: headerNames.join(","),
        },
        payload,
        privateKey: privateKeyPem,
      })
      .split(".");

    return `${header}..${signature}`;
  } catch (e: unknown) {
    const message = hasMessage(e) ? e.message : "Signature error";

    throw new SignatureError(message);
  }
};

type JOSEHeader = {
  alg: jws.Algorithm;
  tl_version: string;
  tl_headers: string;
  kid: string;
  jku: string | undefined;
}

const parseSignature = (signature: string) => {
  try {
    const [header, _, footer] = signature.split(".");
    const headerJson = JSON.parse(Base64.decode(header)) as JOSEHeader;

    SignatureError.ensure(headerJson.alg === "ES512", "unsupported header alg");
    SignatureError.ensure(
      headerJson.tl_version === "2",
      "unsupported header tl_version"
    );

    return {
      headerJson,
      header,
      footer,
    };
  } catch (e: unknown) {
    const message = hasMessage(e) ? e.message : "Signature error";

    throw new SignatureError(message);
  }
};

type SignArguments = {
  kid: string;
  privateKeyPem: string;
  method?: HttpMethod;
  path: string;
  headers?: Record<string, string>;
  body?: string;
};

/** Sign/verification error
 * SignatureError: SignatureError,
 * Produce a JWS `Tl-Signature` v2 header value.
 * @param {Object} args - Arguments.
 * @param {string} args.privateKeyPem - Private key pem.
 * @param {string} args.kid - Private key kid.
 * @param {string} [args.method="POST"] - Request method, e.g. "POST".
 * @param {string} args.path - Request path, e.g. "/payouts".
 * @param {string} [args.body=""] - Request body.
 * @param {Object} [args.headers={}] - Request headers to be signed.
 * Warning: Only a single value per header name is supported.
 * @returns {string} Tl-Signature header value.
 * @throws {SignatureError} Will throw if signing fails.
 */
export function sign(args: SignArguments) {
  const kid = requireArg(args.kid, "kid");
  const privateKeyPem = requireArg(args.privateKeyPem, "privateKeyPem");
  const method = (args.method || HttpMethod.Post).toUpperCase() as HttpMethod;
  const path = requireArg(args.path, "path");
  const headers = new Headers(args.headers || {}).validated();
  const body = args.body || "";

  const payload = buildV2SigningPayload({ method, path, headers, body });

  return signPayload({
    privateKeyPem,
    kid,
    payload,
    headerNames: headers.names(),
  });
}


type BaseParameters = {
  signature: string;
  method: HttpMethod;
  path: string;
  body?: string;
  requiredHeaders?: string[];
  headers?: Record<string, string>;
};

/**
 * @typedef {Object} JwkVerifyParameters
 * @property {string} args.jwks - Public key JWKs JSON response data, alternative to `publicKeyPem`.
 * @property {string} args.signature - Tl-Signature header value.
 * @property {string} args.method - Request method, e.g. "POST".
 * @property {string} args.path - Request path, e.g. "/payouts".
 * @property {string} [args.body=""] - Request body.
 * @property {string[]} [args.requiredHeaders=[]] - List of headers that must be
 *   included in the signature, or else verification will fail.
 * @property {Object} [args.headers={}] - Request headers from which values will
 *   be selectively taken to verify the signature based on what was actually signed.
 */
export type JwkVerifyParameters = BaseParameters & {
  jwks: string;
}

/**
 * @typedef {Object} PublicKeyParameters
 * @param {string} args.publicKeyPem - Public key pem, must be provided unless providing `jwks`.
 * @property {string} args.signature - Tl-Signature header value.
 * @property {string} args.method - Request method, e.g. "POST".
 * @property {string} args.path - Request path, e.g. "/payouts".
 * @property {string} [args.body=""] - Request body.
 * @property {string[]} [args.requiredHeaders=[]] - List of headers that must be
 *   included in the signature, or else verification will fail.
 * @property {Object} [args.headers={}] - Request headers from which values will
 *   be selectively taken to verify the signature based on what was actually signed.
 */
export type PublicKeyParameters = BaseParameters & {
  publicKeyPem: string;
}

/**
* Parameters to verify a given `TL-signature` header value
* @typedef {(JwkVerifyParameters | PublicKeyParameters)} VerifyParameters
*/ 
export type VerifyParameters = JwkVerifyParameters | PublicKeyParameters;


/**
 * Determine if these parameters contain jwks
 * @param args 
 * @returns 
 */
function isJwkParameters(args: VerifyParameters): args is JwkVerifyParameters {
  return 'jwks' in (args as JwkVerifyParameters);
}

/**
 * Verify the given `Tl-Signature` header value.
 * @param {VerifyParameters} args
 * @throws {SignatureError} Will throw if signature could not be verified.
 */
export function verify(args: JwkVerifyParameters): any
export function verify(args: PublicKeyParameters): any 
export function verify(args: VerifyParameters): any {
  const signature = requireArg(args.signature, "signature");
  const { headerJson, header, footer } = parseSignature(signature);

  let publicKeyPem;
  if (isJwkParameters(args)) {
    // find jwk by kid and use as public key
    type Jwks = { keys: Array<Jwk>; }
    type Jwk = jwkToPem.JWK & { kid: string; }

    let jwks: Jwks = JSON.parse(args.jwks);
    let jwk = jwks.keys.find(k => k.kid === headerJson.kid);
    SignatureError.ensure(!!jwk, "no jwk found for signature kid");
    publicKeyPem = jwkToPem(jwk as jwkToPem.JWK);
  } else {
    publicKeyPem = requireArg(args.publicKeyPem, "publicKeyPem");
  }
  
  const method = requireArg(args.method, "method").toUpperCase() as HttpMethod;
  const path = requireArg(args.path, "path");
  const body = args.body || "";
  const requiredHeaders = args.requiredHeaders || [];
  const headers = new Headers(args.headers || {}).validated();

  const tlHeaders = (headerJson.tl_headers || "").split(",").filter(h => !!h);

  // fail if signature is missing a required header
  for (const required of requiredHeaders) {
    const wasSigned = tlHeaders.some(
      (header) => header.toLowerCase() === required.toLowerCase()
    );

    SignatureError.ensure(
      wasSigned,
      `signature is missing required header ${required}`
    );
  }

  headers.retainAndSort(tlHeaders);

  const payload = buildV2SigningPayload({ method, path, headers, body });
  const fullSignature = `${header}.${Base64.encode(payload, true)}.${footer}`;

  if (!jws.verify(fullSignature, headerJson.alg, publicKeyPem)) {
    throw new SignatureError("Invalid signature");
  }
}

/**
 * Extract kid from unverified jws Tl-Signature.
 * @param {string} tlSignature - Tl-Signature header value.
 * @returns {string} Tl-Signature header kid.
 * @throws {SignatureError} Will throw if signature is invalid.
 */
export function extractKid(tlSignature: string): string {
  return parseSignature(tlSignature).headerJson.kid;
}

/**
 * Extract jku from unverified jws Tl-Signature.
 * @param {string} tlSignature - Tl-Signature header value.
 * @returns {string?} Tl-Signature header jku.
 * @throws {SignatureError} Will throw if signature is invalid.
 */
export function extractJku(tlSignature: string): string | undefined {
  return parseSignature(tlSignature).headerJson.jku;
}

export { SignatureError };
