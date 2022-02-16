# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.2
* Add support for verifying jwks with alg: `ES512`.

## 0.1.1
* Add `Verifier.extractJku` to extract `jku` jws header from webhook signatures.
* Add `Verifier.verifyWithJwks` to aid verifying webhook signatures.

## 0.1.0
* Added `Signer` & `Verifier` implementations.
