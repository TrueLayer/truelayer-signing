<?php
declare(strict_types=1);

use Ramsey\Uuid\Uuid;
use TrueLayer\Constants\CustomHeaders;
use TrueLayer\Signing\Signer;
use TrueLayer\Signing\Tests\MockData;

it('should produce a signature', function () {
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4()->toString(), $keys['private']);

    $signer->method('PUT')->path('/test');
    expect($signer->sign())->not->toThrow(Exception::class);
    expect($signer->sign())->toBeString();
});

it('should throw when the request path is not set', function () {
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4()->toString(), $keys['private']);
    $signer->sign();
})->throws(\TrueLayer\Signing\Exceptions\RequestPathNotFoundException::class);

it('should allow signing a request with no headers', function () {
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4()->toString(), $keys['private']);

    $signer->method('POST')
        ->path('/test');

    expect($signer->sign())->not->toThrow(Exception::class);
});

/*
it('some service', function () {
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4()->toString(), $keys['private']);

    $signature = $signer
        ->method('POST')
        ->header('X-CUSTOM', '123')
        ->path('/test')
        ->sign();

    $mock = mock(\Psr\Http\Message\RequestInterface::class);

    $mock->shouldReceive('getMethod')
        ->andReturn('POST');

    $mock->shouldReceive('getHeader')
        ->withArgs([
            'name' => 'X-CUSTOM',
        ])
        ->andReturn('123');

    $mock->shouldReceive('withHeader')
        ->withArgs([
            'key' => \TrueLayer\Signing\Constants\CustomHeaders::SIGNATURE,
            'value' => $signature
        ]);

    $signer->addSignatureHeader($mock);
}); */
