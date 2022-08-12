# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.4
* Add `sign` validation that body is a string.

## 0.1.3
* Add `path` arg validation to `sign` & `verify` for more informative errors.

## 0.1.2
* Add `verify` support for `jwks` arg as an alternative for `publicKeyPem`
  arg when verifying webhook signatures.

## 0.1.1
* Add `verify` support for signatures without headers.
* Add support for TypeScript

## 0.1.0
* Added `sign`, `verify`, `extractKid` methods.
