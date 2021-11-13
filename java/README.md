# truelayer-signing
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