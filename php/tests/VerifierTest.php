<?php
declare(strict_types=1);

use Ramsey\Uuid\Uuid;
use TrueLayer\Signing\Signer;
use TrueLayer\Signing\Verifier;
use TrueLayer\Signing\Tests\MockData;

it('should verify a valid signature', function () {
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4()->toString(), $keys['private']);
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

it('should verify the full request static signature', function () {
    $body = '{"currency":"GBP","max_amount_in_minor":5000000}';
    $idempotencyKey = 'idemp-2076717c-9005-4811-a321-9e0787fa0382';
    $path = '/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping';
    $signature = 'eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2NDktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGVhZGVycyI6IklkZW1wb3RlbmN5LUtleSJ9..AfhpFccUCUKEmotnztM28SUYgMnzPNfDhbxXUSc-NByYc1g-rxMN6HS5g5ehiN5yOwb0WnXPXjTCuZIVqRvXIJ9WAPr0P9R68ro2rsHs5HG7IrSufePXvms75f6kfaeIfYKjQTuWAAfGPAeAQ52PNQSd5AZxkiFuCMDvsrnF5r0UQsGi';

    $verifier = Verifier::verifyWithPemBase64('LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHYk1CQUdCeXFHU000OUFnRUdCU3VCQkFBakE0R0dBQVFCVklWbmdoVXpIbUNFWjNITmpEbWFaTUo3VXdaZgphdjJTWWNFdGJEUWM0dVBoaUV3V29ZWk14emd2c3oxdlZHa3VzZlRJamNYZUNmRForeHU5Z3JSWXQ0a0JvMzl6CncwaTBqMXJhdTRUN0JpK3RoYy9WWnBDeXV3dDYzbVpXY1JzNVBsUXpwTDM0YkJTWEw1TDZHOVhVdFhuOHBYd1UKR01oTkRwNXhWR2JzbFJxVFU4cz0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t');
    $verifier->method('POST')
        ->path($path)
        ->header('X-Whatever-2', 't2345d')
        ->header('Idempotency-Key', $idempotencyKey)
        ->requireHeaders([
            'Idempotency-Key',
        ])
        ->body($body);

    expect($verifier->verify($signature))->not->toThrow(Exception::class);
});

it('should throw when required header is missing', function () {
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4()->toString(), $keys['private'], null);
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
    $signer = Signer::signWithKey(Uuid::uuid4()->toString(), $keys['private'], null);
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
