# truelayer-signing
Kotlin/Java package to produce & verify TrueLayer API requests signatures.

### Kotlin usage
```kotlin
// `Tl-Signature` value to send with the request.
Signer.from(KID, privateKey)
    .header("Idempotency-Key", idempotencyKey)
    .method("post")
    .path(path)
    .body(body)
    .sign()
```

### Java usage
```java
// `Tl-Signature` value to send with the request.
Signer.from(KID, privateKey)
        .header("Idempotency-Key", idempotencyKey)
        .method("post")
        .path(path)
        .body(body)
        .sign();
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
	        implementation 'com.github.truelayer:truelayer-signing:kotlin-{last-version}'
	}
```