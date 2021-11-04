<?php

use Ramsey\Uuid\Uuid;
use TrueLayer\Signing\Signer;
use TrueLayer\Signing\Verifier;
use TrueLayer\Signing\Tests\MockData;

it('should validate a valid signature', function () {
    $signer = Signer::signWithPemBase64(Uuid::uuid4(), MockData::PRIVATE_KEY_PEM_BASE64, null);
    $verifier = Verifier::verifyWithPemBase64(MockData::PUBLIC_KEY_PEM_BASE64);

    $signature = $signer->method("PUT")
        ->path("/test")
        ->header("X-Idempotency-Key", "idempotency-test")
        ->body('{"random-key": "random-value"}')
        ->sign();

    $verifier->method('PUT')
        ->path('/test')
        ->header('X-Idempotency-Key', 'idempotency-test')
        ->body('{"random-key": "random-value"}')
        ->requireHeaders([
            'X-Idempotency-Key'
        ]);

    expect($verifier->verify($signature))->not->toThrow(Exception::class);
});

it('should throw when required header is missing', function () {
    $signer = Signer::signWithPemBase64(Uuid::uuid4(), MockData::PRIVATE_KEY_PEM_BASE64, null);
    $verifier = Verifier::verifyWithPemBase64(MockData::PUBLIC_KEY_PEM_BASE64);

    $signature = $signer->method("PUT")
        ->path("/test")
        ->header("X-Idempotency-Key", "idempotency-test")
        ->body('{"random-key": "random-value"}')
        ->sign();

    $verifier->method("PUT")
        ->path("/test")
        ->header("X-Idempotency-Key", "idempotency-test")
        ->body('{"random-key": "random-value"}')
        ->requireHeaders([
            'X-Idempotency-Key',
            'X-Correlation-Id',
        ])
        ->verify($signature);
})->throws(
    \TrueLayer\Signing\Exceptions\RequiredHeaderMissingException::class,
    'Signature is missing the X-Correlation-Id required header'
);

it('should throw when the signature is invalid', function () {
    $signer = Signer::signWithPemBase64(Uuid::uuid4(), MockData::PRIVATE_KEY_PEM_BASE64, null);
    $verifier = Verifier::verifyWithPemBase64(MockData::PUBLIC_KEY_PEM_BASE64);

    $signature = $signer->method("PUT")
        ->path("/test")
        ->header("X-Idempotency-Key", "idempotency-test")
        ->body('{"random-key": "random-value"}')
        ->sign();

    $verifier->method("PUT")
        ->path("/wrong-path")
        ->header("X-Idempotency-Key", "idempotency-test")
        ->body('{"random-key": "random-value"}')
        ->requireHeaders([
            'X-Idempotency-Key',
        ])
        ->verify($signature);
})->throws(\TrueLayer\Signing\Exceptions\InvalidSignatureException::class);
