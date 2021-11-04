<?php

use Ramsey\Uuid\Uuid;
use TrueLayer\Signing\Signer;
use TrueLayer\Signing\Verifier;
use TrueLayer\Signing\Tests\MockData;

it('should validate a valid signature', function () {
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4(), $keys['private'], null);
    $verifier = Verifier::verifyWithKey($keys['public']);

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
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4(), $keys['private'], null);
    $verifier = Verifier::verifyWithKey($keys['public']);

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
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4(), $keys['private'], null);
    $verifier = Verifier::verifyWithKey($keys['public']);

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
