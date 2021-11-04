<?php

namespace TrueLayer\Signing\Contracts;

interface Signer extends Jws
{
    public static function signWithPem(string $kid, string $pem, ?string $passphrase): self;
    public static function signWithPemBase64(string $kid, string $pemBase64, ?string $passphrase): self;
    public static function signWithPemFile(string $kid, string $path, ?string $passphrase): self;

    public function sign(): string;
}
