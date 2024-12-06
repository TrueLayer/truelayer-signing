<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Encryption;

use TrueLayer\Jose\Component\Checker\HeaderCheckerManagerFactory;
use TrueLayer\Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;

class JWELoaderFactory
{
    public function __construct(
        private JWESerializerManagerFactory $jweSerializerManagerFactory,
        private JWEDecrypterFactory $jweDecrypterFactory,
        private ?HeaderCheckerManagerFactory $headerCheckerManagerFactory
    ) {
    }

    public function create(
        array $serializers,
        array $encryptionAlgorithms,
        array $headerCheckers = []
    ): JWELoader {
        $serializerManager = $this->jweSerializerManagerFactory->create($serializers);
        $jweDecrypter = $this->jweDecrypterFactory->create($encryptionAlgorithms);
        if ($this->headerCheckerManagerFactory !== null) {
            $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);
        } else {
            $headerCheckerManager = null;
        }

        return new JWELoader($serializerManager, $jweDecrypter, $headerCheckerManager);
    }
}
