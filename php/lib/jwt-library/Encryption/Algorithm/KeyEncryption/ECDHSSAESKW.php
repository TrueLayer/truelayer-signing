<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Encryption\Algorithm\KeyEncryption;

use TrueLayer\Jose\Component\Core\JWK;


abstract class ECDHSSAESKW extends AbstractECDHAESKW
{
    /**
     * @param array<string, mixed> $complete_header
     * @param array<string, mixed> $additional_header_values
     */
    public function wrapAgreementKey(
        JWK $recipientKey,
        ?JWK $senderKey,
        string $cek,
        int $encryption_key_length,
        array $complete_header,
        array &$additional_header_values
    ): string {
        $ecdh_ss = new ECDHSS();
        $agreement_key = $ecdh_ss->getAgreementKey(
            $this->getKeyLength(),
            $this->name(),
            $recipientKey->toPublic(),
            $senderKey,
            $complete_header,
            $additional_header_values
        );
        $wrapper = $this->getWrapper();

        return $wrapper::wrap($agreement_key, $cek);
    }

    /**
     * @param array<string, mixed> $complete_header
     */
    public function unwrapAgreementKey(
        JWK $recipientKey,
        ?JWK $senderKey,
        string $encrypted_cek,
        int $encryption_key_length,
        array $complete_header
    ): string {
        $ecdh_ss = new ECDHSS();
        $agreement_key = $ecdh_ss->getAgreementKey(
            $this->getKeyLength(),
            $this->name(),
            $recipientKey,
            $senderKey,
            $complete_header
        );
        $wrapper = $this->getWrapper();

        return $wrapper::unwrap($agreement_key, $encrypted_cek);
    }
}