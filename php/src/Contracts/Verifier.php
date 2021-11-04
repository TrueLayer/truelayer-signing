<?php
declare(strict_types=1);

namespace TrueLayer\Signing\Contracts;

use Jose\Component\Core\JWK;

interface Verifier extends Jws
{
    public static function verifyWithKey(JWK $jwk): self;
    public static function verifyWithPem(string $pem): self;
    public static function verifyWithPemBase64(string $pemBase64): self;
    public static function verifyWithPemFile(string $path): self;

    public function requireHeaders(array $headers): self;
    public function verify(string $signature): void;
}
