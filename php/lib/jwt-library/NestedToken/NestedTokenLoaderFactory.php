<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\NestedToken;

use TrueLayer\Jose\Component\Encryption\JWELoaderFactory;
use TrueLayer\Jose\Component\Signature\JWSLoaderFactory;

class NestedTokenLoaderFactory
{
    public function __construct(
        private readonly JWELoaderFactory $jweLoaderFactory,
        private readonly JWSLoaderFactory $jwsLoaderFactory
    ) {
    }

    /**
     * @param array<string> $jweSerializers
     * @param array<string> $keyEncryptionAlgorithms
     * @param array<string> $jweHeaderCheckers
     * @param array<string> $jwsSerializers
     * @param array<string> $signatureAlgorithms
     * @param array<string> $jwsHeaderCheckers
     */
    public function create(
        array $jweSerializers,
        array $keyEncryptionAlgorithms,
        array $jweHeaderCheckers,
        array $jwsSerializers,
        array $signatureAlgorithms,
        array $jwsHeaderCheckers
    ): NestedTokenLoader {
        $jweLoader = $this->jweLoaderFactory->create($jweSerializers, $keyEncryptionAlgorithms, $jweHeaderCheckers);
        $jwsLoader = $this->jwsLoaderFactory->create($jwsSerializers, $signatureAlgorithms, $jwsHeaderCheckers);

        return new NestedTokenLoader($jweLoader, $jwsLoader);
    }
}
