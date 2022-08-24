# Shared test resources
Shared keys, signatures & values for testing in all languages.

## [ec512-private.pem](./ec512-private.pem)
A valid private key PEM to sign with.
* kid `45fc75cf-5649-4134-84b3-192c2c78e990`

## [ec512-public.pem](./ec512-public.pem)
A valid public key PEM to verify signature signed with **ec512-private.pem**.

## [jwks.json](./jwks.json)
A _.well-known/jwks_ JSON response including a JWK equivalent to **ec512-public.pem**.

## [tl-signature.txt](./tl-signature.txt)
A static `Tl-Signature` signed by **ec512-private.pem** with:
* method `POST`
* path `/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping`
* header `Idempotency-Key: idemp-2076717c-9005-4811-a321-9e0787fa0382`
* body `{"currency":"GBP","max_amount_in_minor":5000000,"name":"Foo???"}`

**All verify implementations should include a test against this signature to ensure cross-lang consistency.**

## [webhook-signature.txt](./webhook-signature.txt)
A static webhook `Tl-Signature` signed by **ec512-private.pem** with:
* additional jws header `jku: https://webhooks.truelayer.com/.well-known/jwks`
* method `POST`
* path `/tl-webhook`
* header `X-Tl-webhook-Timestamp: 2021-11-29T11:42:55Z`
* header `Content-Type: application/json`
* body `{"event_type":"example","event_id":"18b2842b-a57b-4887-a0a6-d3c7c36f1020"}`

This signature may be used to test `jku` JWS header extraction.
