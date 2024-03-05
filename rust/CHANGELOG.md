# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0
* Introduces the Http `Method` enum to replace string literals for HTTP methods, enhancing type safety, code clarity, and a more robust and developer-friendly API.
* The `Signer` has become the `SignerBuilder`: 
  - uses generics for compile time correctness checks 
  - requires an explicit build call
    - `build_custom_signer` requires the kid, method, body(optional of GET requests), and path to be set. It builds a `CustomSigner` which exposes a `sign_with` function.
    - `build_v1_signer` requires private key, kid, and body to be set. It builds a `SignerV1` and exposes a `sign_body_only` function. 
    - `build_signer` requires the private key, kid, body, method, and path to be set. It builds a `Signer` and exposes a `sign` function.
* The `Verifier` has become the `VerifierBuilder`, which uses generics for compile time correctness checks. 
  - uses generics for compile time correctness checks 
  - requires an explit build call
    - `build_v1_verifier` requires the public key and body to be set. It builds a `VerifierV1` and exposes a `verify_body_only` function. 
    - `build_verifier` requires the public key, body, method, and path to be. It builds a `Verifier` and exposed a `verify` and `verify_v1_or_v2` functions.

## 0.1.5
* Improves error handling when parsing and invalid signature.

## 0.1.5
* When verifying permit signed/verified path single trailing slash mismatches.

## 0.1.4
* Add `path` arg assertions to `Signer::path` & `Verifier::path`.
* Use rust edition 2021.

## 0.1.3
* Add support for verifying jwks with alg: `ES512`.

## 0.1.2
* Add `verify_with_jwks` method to aid verifying webhook signatures.

## 0.1.1
* Add support for extracting & setting `jku` in the signature jws header.

## 0.1.0
* Added `truelayer_signing::{sign_with_pem, verify_with_pem, extract_jws_header}`.
