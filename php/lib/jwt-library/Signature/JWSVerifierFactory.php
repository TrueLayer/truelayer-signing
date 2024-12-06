<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Signature;

use TrueLayer\Jose\Component\Core\AlgorithmManagerFactory;

class JWSVerifierFactory
{
    public function __construct(
        private readonly AlgorithmManagerFactory $algorithmManagerFactory
    ) {
    }

    /**
     * Creates a JWSVerifier using the given signature algorithm aliases.
     *
     * @param string[] $algorithms
     */
    public function create(array $algorithms): JWSVerifier
    {
        $algorithmManager = $this->algorithmManagerFactory->create($algorithms);

        return new JWSVerifier($algorithmManager);
    }
}
