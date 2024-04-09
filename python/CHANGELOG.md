# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.4

* Bump black from 22.12.0 to 24.3.0.

## 0.3.3

* Bump cryptography from 42.0.0 to 42.0.4 to address security vulnerabilities.

## 0.3.2

* Update dependencies.

## 0.2.3

* Improves error handling when parsing and invalid signature.

## 0.2.1

* When verifying permit signed/verified path single trailing slash mismatches.
* Add `path` arg assertions to `TlVerifier.set_path(...)` & `TlSigner.set_path(...)`.
* Add `JwsHeader` `dataclass`.

## 0.1.1

* Added `sign_with_pem and verify_with_pem`.
