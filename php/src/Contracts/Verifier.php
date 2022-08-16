<?php

declare(strict_types=1);

namespace TrueLayer\Signing\Contracts;

use Jose\Component\Core\JWK;
use TrueLayer\Signing\Exceptions\InvalidArgumentException;

interface Verifier extends Jws
{
    /**
     * @param array<string, string> ...$decodedJsonObjects
     *
     * @return static
     */
    public static function verifyWithJsonKeys(array ...$decodedJsonObjects): self;

    /**
     * @param JWK ...$jwks
     *
     * @return static
     */
    public static function verifyWithKeys(JWK ...$jwks): self;

    /**
     * @param JWK $jwk
     *
     * @return static
     */
    public static function verifyWithKey(JWK $jwk): self;

    /**
     * @param string ...$pems
     *
     * @throws InvalidArgumentException
     *
     * @return static
     */
    public static function verifyWithPem(string ...$pems): self;

    /**
     * @param string ...$pemsBase64
     *
     * @throws InvalidArgumentException
     *
     * @return static
     */
    public static function verifyWithPemBase64(string ...$pemsBase64): self;

    /**
     * @param string ...$paths
     *
     * @throws InvalidArgumentException
     *
     * @return static
     */
    public static function verifyWithPemFile(string ...$paths): self;

    /**
     * @param string[] $headers
     *
     * @return $this
     */
    public function requireHeaders(array $headers): self;

    /**
     * @param string $signature
     */
    public function verify(string $signature): void;
}
