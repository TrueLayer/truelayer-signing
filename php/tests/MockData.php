<?php

declare(strict_types=1);

namespace TrueLayer\Signing\Tests;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;

class MockData
{
    /**
     * @return array<string, JWK>
     */
    public static function generateKeyPair(): array
    {
        $jwk = JWKFactory::createECKey('P-521');

        return [
            'private' => $jwk,
            'public' => $jwk->toPublic(),
        ];
    }
}
