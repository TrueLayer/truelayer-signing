<?php

namespace TrueLayer\Signing\Contracts;

interface Verifier extends Jws
{
    public static function verifyWithPem(string $pem): self;
    public static function verifyWithPemBase64(string $pemBase64): self;
    public static function verifyWithPemFile(string $path): self;

    public function requireHeaders(array $headers): self;
    public function verify(string $signature): void;
}
