<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Signature;

use Exception;
use TrueLayer\Jose\Component\Checker\HeaderCheckerManager;
use TrueLayer\Jose\Component\Core\JWK;
use TrueLayer\Jose\Component\Core\JWKSet;
use TrueLayer\Jose\Component\Signature\Serializer\JWSSerializerManager;
use Throwable;

/**
 * @see \Truelayer\Jose\Tests\Component\Signature\JWSLoaderTest
 */
class JWSLoader
{
    public function __construct(
        private readonly JWSSerializerManager $serializerManager,
        private readonly JWSVerifier $jwsVerifier,
        private readonly ?HeaderCheckerManager $headerCheckerManager
    ) {
    }

    /**
     * Returns the JWSVerifier associated to the JWSLoader.
     */
    public function getJwsVerifier(): JWSVerifier
    {
        return $this->jwsVerifier;
    }

    /**
     * Returns the Header Checker Manager associated to the JWSLoader.
     */
    public function getHeaderCheckerManager(): ?HeaderCheckerManager
    {
        return $this->headerCheckerManager;
    }

    /**
     * Returns the JWSSerializer associated to the JWSLoader.
     */
    public function getSerializerManager(): JWSSerializerManager
    {
        return $this->serializerManager;
    }

    /**
     * This method will try to load and verify the token using the given key. It returns a JWS and will populate the
     * $signature variable in case of success, otherwise an exception is thrown.
     */
    public function loadAndVerifyWithKey(string $token, JWK $key, ?int &$signature, ?string $payload = null): JWS
    {
        $keyset = new JWKSet([$key]);

        return $this->loadAndVerifyWithKeySet($token, $keyset, $signature, $payload);
    }

    /**
     * This method will try to load and verify the token using the given key set. It returns a JWS and will populate the
     * $signature variable in case of success, otherwise an exception is thrown.
     */
    public function loadAndVerifyWithKeySet(
        string $token,
        JWKSet $keyset,
        ?int &$signature,
        ?string $payload = null
    ): JWS {
        try {
            $jws = $this->serializerManager->unserialize($token);
            $nbSignatures = $jws->countSignatures();
            for ($i = 0; $i < $nbSignatures; ++$i) {
                if ($this->processSignature($jws, $keyset, $i, $payload)) {
                    $signature = $i;

                    return $jws;
                }
            }
        } catch (Throwable) {
            // Nothing to do. Exception thrown just after
        }

        throw new Exception('Unable to load and verify the token.');
    }

    private function processSignature(JWS $jws, JWKSet $keyset, int $signature, ?string $payload): bool
    {
        try {
            if ($this->headerCheckerManager !== null) {
                $this->headerCheckerManager->check($jws, $signature);
            }

            return $this->jwsVerifier->verifyWithKeySet($jws, $keyset, $signature, $payload);
        } catch (Throwable) {
            return false;
        }
    }
}
