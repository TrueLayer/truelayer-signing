# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2022-05-05
### Added
- Support for verifying a signature using JSON keys.
- Support for verifying a signature using `Jose\Component\Core\JWK` keys.

### Changed
- Methods that enable signature verification using PEM or PEM files can now receive multiple strings or paths (i.e multiple keys).
The signature is verified if at least one key verification succeeds.

## [0.0.2] - 2022-01-05
### Changed
- Excluded build/test files when publishing on packagist.

## [0.0.1] - 2021-12-09
### Added
- Support for signing using a PEM string, PEM file, PEM base64 string or `Jose\Component\Core\JWK` key.
- Support for verifying a signature using a PEM string, PEM file, PEM base64 string or `Jose\Component\Core\JWK` key.
