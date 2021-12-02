# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
* Add `Verifier.ExtractJku` to extract `jku` jws header from webhook signatures.
* Add `Verifier.VerifyWithJwks` to aid verifying webhook signatures.

## 0.1.2
* Add `Verifier` support for signatures without headers.
* Fix `Verifier` allowing non-detached jws signatures.
* Fix `Verifier` to throw `SignatureException`s when signature jws headers are missing
  (instead of `KeyNotFoundException`).

## 0.1.1
* Fix changelog path in PackageReleaseNotes.
* Build in release mode & add symbols to package.

## 0.1.0
* Added `Signer` & `Verifier` implementations.
