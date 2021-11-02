"use strict";
exports.__esModule = true;
var jws_1 = require("jws");
var js_base64_1 = require("js-base64");
var error_1 = require("./error");
var headers_1 = require("./headers");
var requireArg = function (arg, name) {
    if (!arg)
        throw new Error("missing argument " + name);
    return arg;
};
var hasMessage = function (e) {
    return typeof e === "object" && e !== null && "message" in e;
};
var buildV2SigningPayload = function (_a) {
    var method = _a.method, path = _a.path, headers = _a.headers, body = _a.body;
    var payload = method + " " + path + "\n";
    for (var _i = 0, _b = headers.entries; _i < _b.length; _i++) {
        var _c = _b[_i], key = _c[0], value = _c[1];
        payload += key + ": " + value + "\n";
    }
    payload += body;
    return payload;
};
var signPayload = function (_a) {
    var privateKeyPem = _a.privateKeyPem, kid = _a.kid, payload = _a.payload, headerNames = _a.headerNames;
    try {
        var _b = jws_1["default"]
            .sign({
            header: {
                alg: "ES512",
                kid: kid,
                tl_version: "2",
                tl_headers: headerNames.join(",")
            },
            payload: payload,
            privateKey: privateKeyPem
        })
            .split("."), header = _b[0], _ = _b[1], signature = _b[2];
        return header + ".." + signature;
    }
    catch (e) {
        var message = hasMessage(e) ? e.message : "Signature error";
        throw new error_1.SignatureError(message);
    }
};
var parseSignature = function (signature) {
    try {
        var _a = signature.split("."), header = _a[0], _ = _a[1], footer = _a[2];
        var headerJson = JSON.parse(js_base64_1.Base64.decode(header));
        error_1.SignatureError.ensure(headerJson.alg === "ES512", "unsupported header alg");
        error_1.SignatureError.ensure(headerJson.tl_version === "2", "unsupported header tl_version");
        return {
            headerJson: headerJson,
            header: header,
            footer: footer
        };
    }
    catch (e) {
        var message = hasMessage(e) ? e.message : "Signature error";
        throw new error_1.SignatureError(message);
    }
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
function sign(args) {
    var kid = requireArg(args.kid, "kid");
    var privateKeyPem = requireArg(args.privateKeyPem, "privateKeyPem");
    var method = (args.method || "POST" /* Post */).toUpperCase();
    var path = requireArg(args.path, "path");
    var headers = new headers_1.Headers(args.headers || {}).validated();
    var body = args.body || "";
    var payload = buildV2SigningPayload({ method: method, path: path, headers: headers, body: body });
    return signPayload({
        privateKeyPem: privateKeyPem,
        kid: kid,
        payload: payload,
        headerNames: headers.names()
    });
}
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
function verify(args) {
    var publicKeyPem = requireArg(args.publicKeyPem, "publicKeyPem");
    var signature = requireArg(args.signature, "signature");
    var method = requireArg(args.method, "method").toUpperCase();
    var path = requireArg(args.path, "path");
    var body = args.body || "";
    var requiredHeaders = args.requiredHeaders || [];
    var headers = new headers_1.Headers(args.headers || {}).validated();
    var _a = parseSignature(signature), headerJson = _a.headerJson, header = _a.header, footer = _a.footer;
    var tlHeaders = (headerJson.tl_headers || "").split(",");
    var _loop_1 = function (required) {
        var wasSigned = tlHeaders.some(function (header) { return header.toLowerCase() === required.toLowerCase(); });
        error_1.SignatureError.ensure(wasSigned, "signature is missing required header " + required);
    };
    // fail if signature is missing a required header
    for (var _i = 0, requiredHeaders_1 = requiredHeaders; _i < requiredHeaders_1.length; _i++) {
        var required = requiredHeaders_1[_i];
        _loop_1(required);
    }
    headers.retainAndSort(tlHeaders);
    var payload = buildV2SigningPayload({ method: method, path: path, headers: headers, body: body });
    var fullSignature = header + "." + js_base64_1.Base64.encode(payload, true) + "." + footer;
    if (!jws_1["default"].verify(fullSignature, headerJson.alg, publicKeyPem)) {
        throw new error_1.SignatureError("Invalid signature");
    }
}
/**
 * Extract kid from unverified jws Tl-Signature.
 * @param {string} tlSignature - Tl-Signature header value.
 * @returns {string} Tl-Signature header kid.
 * @throws {SignatureError} Will throw if signature is invalid.
 */
function extractKid(tlSignature) {
    return parseSignature(tlSignature).headerJson.kid;
}
exports["default"] = {
    sign: sign,
    verify: verify,
    extractKid: extractKid,
    SignatureError: error_1.SignatureError
};
