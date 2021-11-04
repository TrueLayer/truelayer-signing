<?php

use Ramsey\Uuid\Uuid;
use TrueLayer\Signing\Signer;
use TrueLayer\Signing\Tests\MockData;

it('should produce a signature', function () {
    $signer = Signer::signWithPemBase64(Uuid::uuid4(), MockData::PRIVATE_KEY_PEM_BASE64, null);

    $signer->method('PUT')->path('/test');
    expect($signer->sign())->not->toThrow(Exception::class);
    expect($signer->sign())->toBeString();
});

it('should throw when the request path is not set', function () {
    $signer = Signer::signWithPemBase64(Uuid::uuid4(), MockData::PRIVATE_KEY_PEM_BASE64, null);
    $signer->sign();
})->throws(\TrueLayer\Signing\Exceptions\RequestPathNotFoundException::class);
