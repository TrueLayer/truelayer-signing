<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Encryption\Algorithm\KeyEncryption;



final class A256GCMKW extends AESGCMKW
{
    public function name(): string
    {
        return 'A256GCMKW';
    }

    protected function getKeySize(): int
    {
        return 256;
    }
}
