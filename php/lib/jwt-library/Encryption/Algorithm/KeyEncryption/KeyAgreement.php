<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Encryption\Algorithm\KeyEncryption;

use TrueLayer\Jose\Component\Core\JWK;
use TrueLayer\Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;

interface KeyAgreement extends KeyEncryptionAlgorithm
{
    /**
     * Computes the agreement key.
     *
     * @param array<string, mixed> $completeHeader
     * @param array<string, mixed> $additionalHeaderValues
     */
    public function getAgreementKey(
        int $encryptionKeyLength,
        string $algorithm,
        JWK $recipientKey,
        ?JWK $senderKey,
        array $completeHeader = [],
        array &$additionalHeaderValues = []
    ): string;
}
