# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0
* Updated `com.nimbusds:nimbus-jose-jwt` to 10.9.1.
* Migrated from the end-of-life `org.bouncycastle:bcpkix-jdk15on` to `org.bouncycastle:bcpkix-jdk18on` 1.84.
* Updated `com.squareup.okhttp3:okhttp` to 5.4.0 and `org.slf4j:slf4j-simple` to 2.0.18 in the examples.
* Updated the webhook-server example to `io.javalin:javalin` 7.2.2, running on Java 21.
* Updated Gradle to 8.14.5.
* The published library remains Java 8 compatible; CI now runs the test suite on Java 8, 11, 17, 21 and 25.

## 0.2.6
* Force UTF-8 charset when building the payload string.

## 0.2.5
* Improves error handling when parsing and invalid signature.

## 0.2.4
* Update dependencies.

## 0.2.3
* Fix base64 encoding to be url safe.

## 0.2.2
* When verifying permit signed/verified path single trailing slash mismatches.

## 0.2.1
* Add `path` arg validation to `Signer.sign` & `Verifier.verify` for more informative errors.

## 0.2.0
* Move code under `com.truelayer.signing`.
* Publish artifacts to maven central

## 0.1.3
* Add `headers` method to `Verifier` and `Signer`.

## 0.1.2
* Add support for verifying jwks with alg: `ES512`.

## 0.1.1
* Add `Verifier.extractJku` to extract `jku` jws header from webhook signatures.
* Add `Verifier.verifyWithJwks` to aid verifying webhook signatures.

## 0.1.0
* Added `Signer` & `Verifier` implementations.
