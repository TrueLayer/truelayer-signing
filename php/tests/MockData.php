<?php

declare(strict_types=1);

namespace TrueLayer\Signing\Tests;

use TrueLayer\Jose\Component\Core\JWK;
use TrueLayer\Jose\Component\KeyManagement\JWKFactory;
use Ramsey\Uuid\Uuid;

class MockData
{
    /**
     * @param ?string $kid
     *
     * @return array<string, JWK>
     */
    public static function generateKeyPair(?string $kid = null): array
    {
        if (empty($kid)) {
            $kid = Uuid::uuid4()->toString();
        }
        $jwk = JWKFactory::createECKey('P-521', ['kid' => $kid]);

        return [
            'private' => $jwk,
            'public' => $jwk->toPublic(),
        ];
    }
}
