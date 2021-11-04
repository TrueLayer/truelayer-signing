<?php

use Ramsey\Uuid\Uuid;
use TrueLayer\Signing\Signer;
use TrueLayer\Signing\Tests\MockData;

it('should produce a signature', function () {
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4(), $keys['private'], null);

    $signer->method('PUT')->path('/test');
    expect($signer->sign())->not->toThrow(Exception::class);
    expect($signer->sign())->toBeString();
});

it('should throw when the request path is not set', function () {
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4(), $keys['private'], null);
    $signer->sign();
})->throws(\TrueLayer\Signing\Exceptions\RequestPathNotFoundException::class);
