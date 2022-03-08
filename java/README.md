# truelayer-signing
Java package to produce & verify TrueLayer API requests signatures.

```java
// `Tl-Signature` value to send with the request.
Signer.from(kid, privateKey)
        .header("Idempotency-Key", idempotencyKey)
        .method("post")
        .path(path)
        .body(body)
        .sign();
```

### Kotlin usage
```kotlin
// `Tl-Signature` value to send with the request.
Signer.from(kid, privateKey)
    .header("Idempotency-Key", idempotencyKey)
    .method("post")
    .path(path)
    .body(body)
    .sign()
```

### Scala usage
```scala
// `Tl-Signature` value to send with the request.
Signer.from(kid, privateKeyPem)
  .header("Idempotency-Key", idempotencyKey)
  .method("post")
  .path(path)
  .body(body)
  .sign()
```

## Verifying webhooks
The `Verifier.verifyWithJwks` function may be used to verify `Tl-Signature` header signatures.

```java
// `jku` field is included in webhook signatures
String jku = Verifier.extractJku(webhookSignature);

// fetch jwks JSON from the `jku` url (not provided by this lib)
String jwks = fetchJwks(jku):

Verifier.verifyWithJwks(jwks)
        .method("POST")
        .path(path)
        .headers(allWebhookHeaders)
        .body(body)
        .verify(webhookSignature);
```

## Installation
Stable releases are hosted on [Maven Central](https://search.maven.org/search?q=a:truelayer-signing)

``` groovy
	allprojects {
		repositories {
			...
		}
	}
	
	dependencies {
	        implementation 'com.truelayer:truelayer-signing:$version'
	}
```