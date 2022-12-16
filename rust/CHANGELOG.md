# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
