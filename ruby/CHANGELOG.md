# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Disable expiration verification
- ...

## [0.2.0] – 2023-06-13

- Add support for signature verification using a JWKS: `TrueLayerSigning.verify_with_jwks(jwks)`
    and `TrueLayerSigning.extract_jws_header(signature)`.

## [0.1.2] – 2023-05-19

- Fix conflict with JWT library

## [0.1.1] – 2023-05-17

- Fix webhook server example

## [0.1.0] – 2023-01-09

- Add `TrueLayerSigning.sign_with_pem` and `TrueLayerSigning.verify_with_pem(pem)`.
