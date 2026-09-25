# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0
* Add Native AOT and trimming support (`IsAotCompatible`, `IsTrimmable`), using System.Text.Json source generation on .NET 5.0+.
* Remove the `jose-jwt` dependency, JWS signing and verification are now implemented directly on `ECDsa`.
  Consumers using `Jose.*` types transitively must now reference `jose-jwt` explicitly.
* Reduce memory allocations by ~38% for verification (14.73 KB → 9.13 KB) and ~47% for signing (13.47 KB → 7.12 KB).
* `Verify()` with a non P-521 key now fails with `unsupported key, ES512 requires a P-521 key` instead of `Invalid signature`.
* `Microsoft.Extensions.Primitives` is now referenced per target framework (10.0.0 for net10.0, 9.0.11 for net9.0, 8.0.0 otherwise).
* Remove the explicit `System.Text.Encodings.Web` reference.

## 0.2.5
* Bump System.Text.Json from 5.0.1 to 8.0.4

## 0.2.4
* Add support for .NET 10.0.

## 0.2.3
* Add `Verifier.Headers(IEnumerable<KeyValuePair<string, StringValues>>)` overload for direct ASP.NET Core IHeaderDictionary compatibility.
* Performance improvements in `Verifier` reducing memory allocations by ~350-500 bytes per verification (~6% reduction).
* Optimized signature format validation to avoid unnecessary string allocations.
* Improved header parsing on .NET 8.0+ using modern string split options.
* Pre-sized collections to prevent reallocation during verification.
* Optimized missing header validation for better happy path performance.

## 0.2.2
* Use native detached payload verification reducing memory allocations by 34% (45.32 KB → 30.07 KB per verification).
* Remove redundant `.ToLowerInvariant()` call in header lookups.
* Cache `JsonSerializerOptions` for JWKS verification.
* Simplify header trimming logic
* Introduce `JwsHeaders` constants class for better maintainability.

## 0.2.1
* Cache frequently-used UTF8 byte sequences to avoid repeated encoding; remove unnecessary .ToList()
* Include README in NuGet package.

## 0.2.0
* Add support for .NET 8.0 and .NET 9.0.

## 0.1.16
* Add support for providing tl_version and tl_headers via HTTP headers.

## 0.1.15
* Add ability to specify jku when creating signature.

## 0.1.14
* Add ability to sign with a function provided by the consumer.

## 0.1.13
* Improves error handling when parsing and invalid signature.

## 0.1.12
* Verifier `RequireHeader` now matches case insensitively.

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
