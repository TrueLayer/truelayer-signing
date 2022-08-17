# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.11
* When verifying permit signed/verified path single trailing slash mismatches.

## 0.1.10
* Add `path` arg validation to `Signer` & `Verifier` for more informative errors.

## 0.1.9
* Fix key-dependant parameter length error for .NET Standard 2.0.

## 0.1.8
* Fix VerifyWithJwks for pre .NET 5 versions.

## 0.1.7
* Add support for .NET Standard 2.0.

## 0.1.6
* Fix issue parsing jwks with uneven EC coord byte lengths.

## 0.1.5
* Add support for verifying jwks with alg: `ES512`.

## 0.1.4
* Fix `Verifier` allowing non-detached jws signatures with trailing dots.

## 0.1.3
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
