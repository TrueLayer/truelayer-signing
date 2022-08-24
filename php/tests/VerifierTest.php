<?php

declare(strict_types=1);

use Ramsey\Uuid\Uuid;
use TrueLayer\Signing\Signer;
use TrueLayer\Signing\Tests\MockData;
use TrueLayer\Signing\Verifier;

\it('should verify a valid signature', function (string $signedPath, string $verifiedPath) {
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4()->toString(), $keys['private']);
    $verifier = Verifier::verifyWithKey($keys['public']);

    $signature = $signer->method('PUT')
        ->path($signedPath)
        ->header('X-Idempotency-Key', 'idempotency-test')
        ->body('{"random-key": "random-value"}')
        ->sign();

    $verifier->method('PUT')
        ->path($verifiedPath)
        ->header('X-Idempotency-Key', 'idempotency-test')
        ->body('{"random-key": "random-value"}')
        ->requireHeaders([
            'X-Idempotency-Key',
        ]);

    /* @phpstan-ignore-next-line */
    \expect($verifier->verify($signature))->not->toThrow(Exception::class);
})->with([
    ['/test', '/test'],
    ['/test', '/test/'],
    ['/test/', '/test'],
    ['/test/', '/test/'],
]);

\it('should verify the full request static signature', function () {
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

    /* @phpstan-ignore-next-line */
    \expect($verifier->verify($signature))->not->toThrow(Exception::class);
});

\it('should throw when required header is missing', function () {
    $kid = Uuid::uuid4()->toString();
    $keys = MockData::generateKeyPair($kid);
    $signer = Signer::signWithKey($kid, $keys['private']);
    $verifier = Verifier::verifyWithKey($keys['public']);

    $signature = $signer->method('PUT')
        ->path('/test')
        ->header('X-Idempotency-Key', 'idempotency-test')
        ->body('{"random-key": "random-value"}')
        ->sign();

    $verifier->method('PUT')
        ->path('/test')
        ->header('X-Idempotency-Key', 'idempotency-test')
        ->body('{"random-key": "random-value"}')
        ->requireHeaders([
            'X-Idempotency-Key',
            'X-Correlation-Id',
        ])
        ->verify($signature);
})->throws(
    \TrueLayer\Signing\Exceptions\RequiredHeaderMissingException::class,
    'Signature is missing the x-correlation-id required header'
);

\it('should throw when the signature is invalid', function () {
    $kid = Uuid::uuid4()->toString();
    $keys = MockData::generateKeyPair($kid);
    $signer = Signer::signWithKey($kid, $keys['private']);
    $verifier = Verifier::verifyWithKey($keys['public']);

    $signature = $signer->method('PUT')
        ->path('/test')
        ->header('X-Idempotency-Key', 'idempotency-test')
        ->body('{"random-key": "random-value"}')
        ->sign();

    $verifier->method('PUT')
        ->path('/wrong-path')
        ->header('X-Idempotency-Key', 'idempotency-test')
        ->body('{"random-key": "random-value"}')
        ->requireHeaders([
            'X-Idempotency-Key',
        ])
        ->verify($signature);
})->throws(\TrueLayer\Signing\Exceptions\InvalidSignatureException::class);

\it('should verify header order/casing flexibility', function () {
    $kid = Uuid::uuid4()->toString();
    $keys = MockData::generateKeyPair($kid);
    $signer = Signer::signWithKey($kid, $keys['private']);
    $verifier = Verifier::verifyWithKey($keys['public']);

    $signature = $signer->method('PUT')
        ->path('/test')
        ->headers([
            'Idempotency-Key' => 'test',
            'X-Custom' => '123',
        ])
        ->body('{"random-key": "random-value"}')
        ->sign();

    $verifier->method('PUT')
        ->path('/test')
        ->headers([
            'X-custom' => '123', // different order & case, it's ok!
            'X-Whatever-2' => 'foaulrsjth',
            'idempotency-key' => 'test', // different order & case, chill it'll work!
        ])
        ->body('{"random-key": "random-value"}')
        ->requireHeaders([
            'IDEMPOTENCY-Key', // different case
        ]);

    /* @phpstan-ignore-next-line */
    \expect($verifier->verify($signature))->not->toThrow(Exception::class);
});

\it('should not verify the wrong HTTP method', function () {
    $kid = Uuid::uuid4()->toString();
    $keys = MockData::generateKeyPair($kid);
    $signer = Signer::signWithKey($kid, $keys['private']);
    $verifier = Verifier::verifyWithKey($keys['public']);

    $signature = $signer->method('PUT')
        ->path('/test')
        ->headers([
            'Idempotency-Key' => 'test',
            'X-Custom' => '123',
        ])
        ->body('{"random-key": "random-value"}')
        ->sign();

    $verifier->method('POST')
        ->path('/test')
        ->headers([
            'Idempotency-Key' => 'test',
            'X-Custom' => '123',
        ])
        ->body('{"random-key": "random-value"}')
        ->requireHeaders([
            'Idempotency-Key',
        ])
        ->verify($signature);
})->throws(\TrueLayer\Signing\Exceptions\InvalidSignatureException::class);

\it('should verify a signature that has no headers', function () {
    $kid = Uuid::uuid4()->toString();
    $keys = MockData::generateKeyPair($kid);
    $signer = Signer::signWithKey($kid, $keys['private']);
    $verifier = Verifier::verifyWithKey($keys['public']);

    $signature = $signer->method('POST')
        ->path('/test')
        ->body('{"random-key": "random-value"}')
        ->sign();

    $verifier->method('POST')
        ->path('/test')
        ->body('{"random-key": "random-value"}');

    /* @phpstan-ignore-next-line */
    \expect($verifier->verify($signature))->not->toThrow(Exception::class);
});

\it('should not verify a signature that has an attached payload', function () {
    $signature = 'eyJhbGciOiJFUzUxMiIsImtpZCI6ImU5OTYzOTNmLWFiZGQtNDc4ZS1iZDIzLTZlYTU4OGJhY2IzMyIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGVhZGVycyI6IiJ9.UFVUIC90ZXN0CnsicmFuZG9tLWtleSI6ICJyYW5kb20tdmFsdWUifQ.AVfKw5gNZCKTfa7p_z4S7RQs6qpqWFTbg7x-Rv-1wmPffPCNBktVwbxTu5I359pP6ilFTTgS0IR58JKkDbRE2NqsALDh08EYea17dfZPUaDFh7E8r9eOHllrHTGyF2mKj9rRILoBauYgRJ3shAG2XBIL6GB6tklchUGJHxsRXA0bTp8M';

    $keys = MockData::generateKeyPair();
    $verifier = Verifier::verifyWithKey($keys['public']);

    $verifier->verify($signature);
})->throws(\TrueLayer\Signing\Exceptions\SignatureMustUseDetachedPayloadException::class);

\it('should verify a valid signature from pem string', function () {
    $privateKey = \file_get_contents(__DIR__ . '/ec512-private.pem') ?: '';
    $publicKey = \file_get_contents(__DIR__ . '/ec512-public.pem') ?: '';
    $signer = Signer::signWithPem(Uuid::uuid4()->toString(), $privateKey, null);
    $signer->method('PUT')->path('/test');

    $verifier = Verifier::verifyWithPem($publicKey);

    $signature = $signer->method('PUT')
        ->path('/test')
        ->header('X-Idempotency-Key', 'idempotency-test')
        ->body('{"random-key": "random-value"}')
        ->sign();

    $verifier->method('PUT')
        ->path('/test')
        ->header('X-Idempotency-Key', 'idempotency-test')
        ->body('{"random-key": "random-value"}')
        ->requireHeaders([
            'X-Idempotency-Key',
        ]);

    /* @phpstan-ignore-next-line */
    \expect($verifier->verify($signature))->not->toThrow(Exception::class);
});

\it('should verify a valid signature from decoded json', function () {
    $signature = \file_get_contents('../test-resources/tl-signature.txt');
    $jwksJson = \file_get_contents('../test-resources/jwks.json');

    /**
     * @var array<string, array<array<string, string>>> $jwks
     */
    $jwks = \json_decode((string) $jwksJson, true);
    $verifier = Verifier::verifyWithJsonKeys(...$jwks['keys']);

    $verifier->method('POST')
        ->path('/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping')
        ->header('X-Whatever-2', 't2345d')
        ->header('Idempotency-Key', 'idemp-2076717c-9005-4811-a321-9e0787fa0382')
        ->body('{"currency":"GBP","max_amount_in_minor":5000000,"name":"Foo???"}');

    /* @phpstan-ignore-next-line */
    \expect($verifier->verify($signature))->not->toThrow(Exception::class);
});
