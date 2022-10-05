# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
