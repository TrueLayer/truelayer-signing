<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Signature\Algorithm;

use InvalidArgumentException;
use TrueLayer\Jose\Component\Core\JWK;
use TrueLayer\Jose\Component\Core\Util\Base64UrlSafe;

use function in_array;
use function is_string;

abstract class HMAC implements MacAlgorithm
{
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    public function verify(JWK $key, string $input, string $signature): bool
    {
        return hash_equals($this->hash($key, $input), $signature);
    }

    public function hash(JWK $key, string $input): string
    {
        $k = $this->getKey($key);

        return hash_hmac($this->getHashAlgorithm(), $input, $k, true);
    }

    protected function getKey(JWK $key): string
    {
        if (! in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
        if (! $key->has('k')) {
            throw new InvalidArgumentException('The key parameter "k" is missing.');
        }
        $k = $key->get('k');
        if (! is_string($k)) {
            throw new InvalidArgumentException('The key parameter "k" is invalid.');
        }

        return Base64UrlSafe::decodeNoPadding($k);
    }

    abstract protected function getHashAlgorithm(): string;
}
