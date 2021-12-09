<?php

declare(strict_types=1);

namespace TrueLayer\Signing\Contracts;

use Jose\Component\Core\JWK;
use Psr\Http\Message\RequestInterface;

interface Signer extends Jws
{
    public static function signWithKey(string $kid, JWK $jwk): self;

    public static function signWithPem(string $kid, string $pem, ?string $passphrase = null): self;

    public static function signWithPemBase64(string $kid, string $pemBase64, ?string $passphrase = null): self;

    public static function signWithPemFile(string $kid, string $path, ?string $passphrase = null): self;

    public function sign(): string;

    public function addSignatureHeader(RequestInterface $request): RequestInterface;
}
