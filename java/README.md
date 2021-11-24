# truelayer-signing
[![](https://jitpack.io/v/truelayer/truelayer-signing.svg)](https://jitpack.io/#truelayer/truelayer-signing)

Java package to produce & verify TrueLayer API requests signatures.

### Java usage
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
## Installation
``` groovy
	allprojects {
		repositories {
			...
			maven { url 'https://jitpack.io' }
		}
	}
	
	dependencies {
	        implementation 'com.github.truelayer:truelayer-signing:java-{last-version}'
	}
```

## Examples

Find more examples in [Kotlin](./examples/kotlin/src/main/kotlin/truelayer/signing/Example.kt) and [Scala](./examples/scala/src/main/scala/truelayer/signing/Example.scala).