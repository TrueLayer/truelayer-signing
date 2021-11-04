<?php

namespace TrueLayer\Signing\Tests;

use Jose\Component\KeyManagement\JWKFactory;

class MockData {
    public static function generateKeyPair(): array
    {
        $jwk = JWKFactory::createECKey('P-521');

        return [
            'private' => $jwk,
            'public' => $jwk->toPublic(),
        ];
    }
}
