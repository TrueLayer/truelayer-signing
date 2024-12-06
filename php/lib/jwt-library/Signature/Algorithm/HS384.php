<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Signature\Algorithm;

use InvalidArgumentException;
use TrueLayer\Jose\Component\Core\JWK;

use function strlen;

final class HS384 extends HMAC
{
    public function name(): string
    {
        return 'HS384';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha384';
    }

    protected function getKey(JWK $key): string
    {
        $k = parent::getKey($key);
        if (strlen($k) < 48) {
            throw new InvalidArgumentException('Invalid key length.');
        }

        return $k;
    }
}
