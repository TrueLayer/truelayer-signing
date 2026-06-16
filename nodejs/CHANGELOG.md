# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.3]

- Bump @babel/core from 7.28.5 to 7.29.7 in /nodejs
- Bump axios from 1.13.2 to 1.16.0 in /nodejs/examples/webhook-server
- Bump axios from 1.13.2 to 1.15.0 in /nodejs/examples/sign-request
- Bump handlebars from 4.7.8 to 4.7.9 in /nodejs
- Bump picomatch from 2.3.1 to 2.3.2 in /nodejs
- Bump minimatch from 3.1.2 to 3.1.5 in /nodejs
- Bump bn.js from 4.12.2 to 4.12.3 in /nodejs/examples/aws-kms-sign
- Bump bn.js from 4.12.2 to 4.12.3 in /nodejs/examples/sign-request
- Bump bn.js from 4.12.2 to 4.12.3 in /nodejs
- Bump qs from 6.14.1 to 6.14.2 in /nodejs/examples/webhook-server
- Update remaining dependencies in library:
  - jws 4.0.0 → 4.0.1
  - ts-jest 29.4.5 → 29.4.11
  - @types/node 24.10.1 → 24.13.2
- Update remaining dependencies in examples:
  - sign-request: axios → 1.18.0
  - webhook-server: axios → 1.18.0, express → 5.2.1
  - aws-kms-sign: @aws-sdk/client-kms → 3.1069.0

## [0.2.2]

- Bump qs from 6.14.0 to 6.14.1
- Bump express from 5.1.0 to 5.2.0

## [0.2.1]

- Bump body-parser from 2.2.0 to 2.2.1
- Update dependencies in Node.js examples

## [0.2.0]

- Upgrade Node.js dependencies

## [0.1.9]

- Bump js-yaml from 3.14.1 to 3.14.2
- bump actions/setup-node from 4 to 6
- Bump axios from 1.8.2 to 1.12.0
- Bump form-data from 3.0.1 to 3.0.4

## [0.1.8]

- Add tests for nested JSON and special chars
- Update dependencies

## [0.1.7]

### Added

- Add `sign` method overload to allow signing using a KMS/HSM managed key.

## [0.1.6]

### Fixed

- Improves error handling when parsing and invalid signature.

## [0.1.5]

### Changed

- When verifying permit signed/verified path single trailing slash mismatches.

## [0.1.4]

### Fixed

- Add `sign` validation that body is a string.

## [0.1.3]

### Fixed

- Add `path` arg validation to `sign` & `verify` for more informative errors.

## [0.1.2]

### Added

- Add `verify` support for `jwks` arg as an alternative for `publicKeyPem` arg when verifying webhook signatures.

## [0.1.1]

### Added

- Add `verify` support for signatures without headers.
- Add support for TypeScript

## [0.1.0]

### Added

- Added `sign`, `verify`, `extractKid` methods.
