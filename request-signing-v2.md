# Request Signing (v2)

Signing requests provides a second layer of security on top of the authorisation bearer token and guarantees that the payload has not been tampered with.

## Supported Algorithms
We only support [ES512](https://tools.ietf.org/html/rfc7518#page-9) [signing algorithm](https://tools.ietf.org/html/rfc7518) for modification requests to our Payments APIs.

## Generate Signing Key Pair
ES512 belongs to the family of [Elliptic Curve Digital Signature Algorithms (ECDSA)](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm).
To sign an HTTP request using ECDSA you will need to generate an Elliptic Curve (EC) [key pair](https://en.wikipedia.org/wiki/Public-key_cryptography). You will need:

- a public key, to be provided to the verifying party.
- a private key, to be used for signing requests, which you should **not** share with anyone outside of your organisation.

ES512, in particular, requires a key pair that use the P-521 family of elliptic curves (also known as `secpt521r1`).
You can generate a key pair using [`openssl`](https://www.openssl.org/).
To generate the private key, run:

```bash
docker run --rm -v ${PWD}:/out -w /out -it alpine/openssl ecparam -genkey -name secp521r1 -noout -out ec512-private-key.pem
```

You can then obtain the public key by running:

```bash
docker run --rm -v ${PWD}:/out -w /out -it alpine/openssl ec -in ec512-private-key.pem -pubout -out ec512-public-key.pem
```

`ec512-public-key.pem` is the file you should upload in the **NEW** Payments Settings page in our Console.

## Sign a request
You need to specify a `Tl-Signature` header in your HTTP request.
The header value is a [JWS with detached content](https://tools.ietf.org/html/rfc7515#appendix-F), signed using the ES512 algorithm.  

A JWS with detached content has the following structure:

```txt
<Base64URLSafeEncoding(JOSEHeader)>..<Base64URLSafeEncoding(signature)>
````

The payload segment is omitted in the JWS with detached content to generate the signature.

The JOSE header must contain:
- The `alg` header parameter, with `ES512` as value;
- The `kid` header parameter, with the id of the key used for signing as value (i.e. the UUID value shown in the **NEW** Payments Settings in Console next to your uploaded public key);
- The `tl_version` header parameter, with `"2"` as value;
- The `tl_headers` header parameter, with an ordered comma separated list of headers to include in signing (must at least include `Idempotency-Key`) as value.

For example:

```json
{
    "alg": "ES512",
    "kid": "9f2b7bd6-c055-40b5-b616-120ccfd33c49",
    "tl_version": "2",
    "tl_headers": "Idempotency-Key"
}
```

The JWS payload should be built using the following in order:
- The HTTP VERB (capitalized), followed by a space, then the absolute path (without trailing slashes) e.g.: `POST /payouts`, followed by a newline character `\n`
- For each header specified in `tl_headers`, in the same order (and with the same casing):
    - The header name, followed by a colon, a space, then the header value, e.g.: `Idempotency-Key: 619410b3-b00c-406e-bb1b-2982f97edb8b`, followed by a newline character `\n`
- The serialized HTTP request body (if sending a body)

For example:

```txt
POST /payouts
Idempotency-Key: 619410b3-b00c-406e-bb1b-2982f97edb8b
{"currency":"GBP","amount_in_minor":100}
```
