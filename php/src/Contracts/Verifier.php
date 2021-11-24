<?php

declare(strict_types=1);

namespace TrueLayer\Signing\Contracts;

use Jose\Component\Core\JWK;

interface Verifier extends Jws
{
    /**
     * @param JWK $jwk
     *
     * @return static
     */
    public static function verifyWithKey(JWK $jwk): self;

    /**
     * @param string $pem
     *
     * @return static
     */
    public static function verifyWithPem(string $pem): self;

    /**
     * @param string $pemBase64
     *
     * @return static
     */
    public static function verifyWithPemBase64(string $pemBase64): self;

    /**
     * @param string $path
     *
     * @return static
     */
    public static function verifyWithPemFile(string $path): self;

    /**
     * @param array<string, string> $headers
     *
     * @return $this
     */
    public function requireHeaders(array $headers): self;

    /**
     * @param string $signature
     */
    public function verify(string $signature): void;
}
