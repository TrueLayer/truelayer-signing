<?php

declare(strict_types=1);

use Ramsey\Uuid\Uuid;
use TrueLayer\Signing\Exceptions\RequestPathNotFoundException;
use TrueLayer\Signing\Signer;
use TrueLayer\Signing\Tests\MockData;

\it('should produce a signature', function () {
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4()->toString(), $keys['private']);

    $signer->method('PUT')->path('/test');
    \expect($signer->sign())->not->toThrow(Exception::class);
    \expect($signer->sign())->toBeString();
});

\it('should throw when the request path is not set', function () {
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4()->toString(), $keys['private']);
    $signer->sign();
})->throws(RequestPathNotFoundException::class);

\it('should allow signing a request with no headers', function () {
    $keys = MockData::generateKeyPair();
    $signer = Signer::signWithKey(Uuid::uuid4()->toString(), $keys['private']);

    $signer->method('POST')
        ->path('/test');

    \expect($signer->sign())->not->toThrow(Exception::class);
});

/*
 * @throws RequestPathNotFoundException
 */
\it('should allow signing classes implementing PSR7 interfaces', function () {
    $keys = MockData::generateKeyPair();
    $kid = Uuid::uuid4()->toString();
    $path = '/test';
    $method = 'POST';
    $body = '{"random-key": "random-value"}';

    $uriMock = \Mockery::mock(\Psr\Http\Message\UriInterface::class);
    $uriMock->shouldReceive('getPath')->andReturn($path);

    $requestMock = \Mockery::mock(\Psr\Http\Message\RequestInterface::class);
    $requestMock->shouldReceive('getUri')->andReturn($uriMock);
    $requestMock->shouldReceive('getMethod')->andReturn($method);
    $requestMock->shouldReceive('getBody')->andReturn($body);
    $requestMock->shouldReceive('getHeaders')->andReturn([
        'X-CUSTOM' => ['123'],
    ]);

    $requestMock->shouldReceive('withHeader')
        ->with(
            \TrueLayer\Signing\Constants\CustomHeaders::SIGNATURE,
            \Mockery::on(function ($signature) use ($keys, $path, $method, $body) {
                $verifier = \TrueLayer\Signing\Verifier::verifyWithKey($keys['public']);

                $verifier
                    ->path($path)
                    ->method($method)
                    ->body($body)
                    ->headers([
                        'X-CUSTOM' => '123',
                    ])
                    ->verify($signature);

                return true;
            })
        )
        ->andReturn($requestMock);

    $signer = Signer::signWithKey($kid, $keys['private']);

    $signer->addSignatureHeader($requestMock);
    $signer->method('POST')
        ->path('/test');

    \expect($signer->sign())->not->toThrow(Exception::class);
});
