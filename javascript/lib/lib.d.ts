import { SignatureError } from "./error";
declare const enum HttpMethod {
    Post = "POST",
    Get = "GET",
    Patch = "PATCH",
    Put = "PUT",
    Delete = "DELETE"
}
declare type VerifyArguments = {
    kid: string;
    privateKeyPem: string;
    method: HttpMethod;
    path: string;
    headers: Record<string, string>;
    body: string;
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
declare function sign(args: VerifyArguments): string;
declare type VerifyParameters = {
    publicKeyPem: string;
    signature: string;
    method: HttpMethod;
    path: string;
    body: string;
    requiredHeaders: string[];
    headers: Record<string, string>;
};
/**
 * Verify the given `Tl-Signature` header value.
 * @param {Object} args - Arguments.
 * @param {string} args.publicKeyPem - Public key pem.
 * @param {string} args.signature - Tl-Signature header value.
 * @param {string} args.method - Request method, e.g. "POST".
 * @param {string} args.path - Request path, e.g. "/payouts".
 * @param {string} [args.body=""] - Request body.
 * @param {string[]} [args.requiredHeaders=[]] - List of headers that must be
 * included in the signature, or else verification will fail.
 * @param {Object} [args.headers={}] - Request headers from which values will
 * be selectively taken to verify the signature based on what was actuall signed.
 * @throws {SignatureError} Will throw if signature could not be verified.
 */
declare function verify(args: VerifyParameters): void;
/**
 * Extract kid from unverified jws Tl-Signature.
 * @param {string} tlSignature - Tl-Signature header value.
 * @returns {string} Tl-Signature header kid.
 * @throws {SignatureError} Will throw if signature is invalid.
 */
declare function extractKid(tlSignature: string): string;
declare const _default: {
    sign: typeof sign;
    verify: typeof verify;
    extractKid: typeof extractKid;
    SignatureError: typeof SignatureError;
};
export default _default;
