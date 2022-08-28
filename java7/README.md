# truelayer-signing
Java package to produce & verify TrueLayer API requests signatures.

Usage in java/scala/kotlin code.
```java
// `Tl-Signature` value to send with the request.
Signer.from(kid, privateKey)
        .header("Idempotency-Key", idempotencyKey)
        .method("post")
        .path(path)
        .body(body)
        .sign();
```

See [full example](./examples/sign-request/).

## Verifying webhooks
The `Verifier.verifyWithJwks` function may be used to verify `Tl-Signature` header signatures.

```java
// `jku` field is included in webhook signatures
String jku = Verifier.extractJku(webhookSignature);

// check `jku` is an allowed TrueLayer url & fetch jwks JSON (not provided by this lib)
ensureJkuAllowed(jku);
String jwks = fetchJwks(jku);

Verifier.verifyWithJwks(jwks)
        .method("POST")
        .path(path)
        .headers(allWebhookHeaders)
        .body(body)
        .verify(webhookSignature);
```

See [webhook server example](./examples/webhook-server/).

## Installation
Stable releases are hosted on [Maven Central](https://search.maven.org/search?q=a:truelayer-signing)

``` groovy
	dependencies {
	        implementation 'com.truelayer:truelayer-signing:$version'
	}
```
