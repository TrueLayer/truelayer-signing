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
  if (!path.startsWith('/')) {
    throw new Error(`Invalid path \"${path}\" must start with '/'`);
  }
  if (!(typeof body === 'string' || (body as any) instanceof String)) {
    throw new Error(`Invalid body '${typeof body}' type must be a string`);
  }

  let payload = `${method} ${path}\n`;

  for (const [key, value] of headers.entries) {
    payload += `${key}: ${value}\n`;
  }

  payload += body;
  return payload;
};

type SignPayloadConfigCommon = {
  kid: string;
  payload: string;
  headerNames: string[];
};

type SignPayloadConfig = SignPayloadConfigCommon & {
  privateKeyPem: string;
};

type SignPayloadWithFunctionConfig = SignPayloadConfigCommon & {
  sign: (message: string) => Promise<string>;
};

const createJwsHeader = (kid: string, headerNames: string[]): jws.Header => {
  return {
    alg: "ES512",
    kid,
    tl_version: "2",
    tl_headers: headerNames.join(","),
  };
};

const signPayloadWithPem = ({
  privateKeyPem,
  kid,
  payload,
  headerNames,
}: SignPayloadConfig) => {
  try {
    const [header, _, signature] = jws
      .sign({
        header: createJwsHeader(kid, headerNames),
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

const signPayloadWithFunction = async ({
  sign,
  kid,
  payload,
  headerNames,
}: SignPayloadWithFunctionConfig): Promise<string> => {
  try {
    const jwsComponents = {
      header: Base64.encodeURI(JSON.stringify(createJwsHeader(kid, headerNames))),
      payload: Base64.encodeURI(payload),
    };
    const jwsSigningMessage = `${jwsComponents.header}.${jwsComponents.payload}`;
    const signature = await sign(jwsSigningMessage);
    return `${jwsComponents.header}..${signature}`;
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

    let headerJson = parseHeader(header);
    
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

function parseHeader(header: string): JOSEHeader {
  let headerJson: JOSEHeader | undefined = undefined;
  try {
    headerJson = JSON.parse(Base64.decode(header)) as JOSEHeader;
  } catch (error) {
    if (error instanceof Error) {
      throw new SignatureError("Failed to parse JWS: " + error.message);
    } else {
      throw new SignatureError("Failed to parse JWS");
    }
  }
  if (headerJson === undefined) {
    throw new SignatureError("Failed to parse JWS");
  }
  return headerJson;
}

type SignBaseArguments = {
  kid: string;
  method?: HttpMethod;
  path: string;
  headers?: Record<string, string>;
  body?: string;
};

/**
 * @typedef {Object} SignWithPemArguments
 * @property {string} kid - Private key kid.
 * @property {string} [method="POST"] - Request method, e.g. "POST".
 * @property {string} path - Request path, e.g. "/payouts".
 * @property {Record<string, string>} [headers={}] - Request headers to be signed.
 * @property {string} [body=""] - Request body.
 * @property {string} privateKeyPem - Private key pem.
 */
export type SignWithPemArguments = SignBaseArguments & {
  privateKeyPem: string;
};

/**
 * @typedef {Object} SignWithFunctionArguments
 * @property {string} kid - Private key kid.
 * @property {string} [method="POST"] - Request method, e.g. "POST".
 * @property {string} path - Request path, e.g. "/payouts".
 * @property {Record<string, string>} [headers={}] - Request headers to be signed.
 * @property {string} [body=""] - Request body.
 * @property {(string) => Promise<string>} sign - Function to sign using a KMS/HSM.
 */
export type SignWithFunctionArguments = SignBaseArguments & {
  sign: (message: string) => Promise<string>;
};

export type SignArguments = SignWithPemArguments | SignWithFunctionArguments;

function isSignWithPemArguments(args: SignArguments): args is SignWithPemArguments {
  return 'privateKeyPem' in (args as SignWithPemArguments);
}

/** Sign/verification error
 * SignatureError: SignatureError,
 * Produce a JWS `Tl-Signature` v2 header value.
 * @param {SignWithPemArguments} args - Arguments.
 * @returns {string} Tl-Signature header value.
 * @throws {SignatureError} Will throw if signing fails.
 */
export function sign(args: SignWithPemArguments): string;
/** Sign/verification error
 * SignatureError: SignatureError,
 * Produce a JWS `Tl-Signature` v2 header value.
 * @param {SignWithFunctionArguments} args - Arguments.
 * @returns {Promise<string>} Tl-Signature header value.
 * @throws {SignatureError} Will throw if signing fails.
 */
export function sign(args: SignWithFunctionArguments): Promise<string>;
export function sign(args: SignArguments): any {
  const kid = requireArg(args.kid, "kid");
  const method = (args.method || HttpMethod.Post).toUpperCase() as HttpMethod;
  const path = requireArg(args.path, "path");
  const headers = new Headers(args.headers || {}).validated();
  const body = args.body || "";

  const payload = buildV2SigningPayload({ method, path, headers, body });

  if (isSignWithPemArguments(args)) {
    const privateKeyPem = requireArg(args.privateKeyPem, "privateKeyPem");
    return signPayloadWithPem({
      privateKeyPem,
      kid,
      payload,
      headerNames: headers.names(),
    });
  } else {
    const sign = requireArg(args.sign, "sign");
    return signPayloadWithFunction({
      sign,
      kid,
      payload,
      headerNames: headers.names(),
    });
  }
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
    // try again with/without a trailing slash (#80)
    let path2 = path + '/';
    if (path.endsWith('/')) {
      path2 = path.slice(0, path.length - 1);
    }
    const payload = buildV2SigningPayload({ method, path: path2, headers, body });
    const fullSignature = `${header}.${Base64.encode(payload, true)}.${footer}`;
    if (!jws.verify(fullSignature, headerJson.alg, publicKeyPem)) {
      throw new SignatureError("Invalid signature");
    }
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
