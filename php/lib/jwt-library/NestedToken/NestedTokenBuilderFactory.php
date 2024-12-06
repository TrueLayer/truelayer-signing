<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\NestedToken;

use TrueLayer\Jose\Component\Encryption\JWEBuilderFactory;
use TrueLayer\Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use TrueLayer\Jose\Component\Signature\JWSBuilderFactory;
use TrueLayer\Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;

class NestedTokenBuilderFactory
{
    public function __construct(
        private readonly JWEBuilderFactory $jweBuilderFactory,
        private readonly JWESerializerManagerFactory $jweSerializerManagerFactory,
        private readonly JWSBuilderFactory $jwsBuilderFactory,
        private readonly JWSSerializerManagerFactory $jwsSerializerManagerFactory
    ) {
    }

    /**
     * @param array<string> $jwe_serializers
     * @param array<string> $encryptionAlgorithms
     * @param array<string> $jws_serializers
     * @param array<string> $signatureAlgorithms
     */
    public function create(
        array $jwe_serializers,
        array $encryptionAlgorithms,
        array $jws_serializers,
        array $signatureAlgorithms
    ): NestedTokenBuilder {
        $jweBuilder = $this->jweBuilderFactory->create($encryptionAlgorithms);
        $jweSerializerManager = $this->jweSerializerManagerFactory->create($jwe_serializers);
        $jwsBuilder = $this->jwsBuilderFactory->create($signatureAlgorithms);
        $jwsSerializerManager = $this->jwsSerializerManagerFactory->create($jws_serializers);

        return new NestedTokenBuilder($jweBuilder, $jweSerializerManager, $jwsBuilder, $jwsSerializerManager);
    }
}
