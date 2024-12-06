<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Encryption\Algorithm\KeyEncryption;

use TrueLayer\Jose\Component\Core\JWK;
use TrueLayer\Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;

interface DirectEncryption extends KeyEncryptionAlgorithm
{
    /**
     * Returns the CEK.
     *
     * @param JWK $key The key used to get the CEK
     */
    public function getCEK(JWK $key): string;
}
