<?php

declare(strict_types=1);

namespace TrueLayer\SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519;

use TrueLayer\SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\X25519AlgorithmIdentifier;
use TrueLayer\SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;

/**
 * Implements an intermediary object to store X25519 public key.
 *
 * @see https://tools.ietf.org/html/rfc8410
 */
final class X25519PublicKey extends Curve25519PublicKey
{
    public static function create(string $publicKey): self
    {
        return new self($publicKey);
    }

    public function algorithmIdentifier(): AlgorithmIdentifierType
    {
        return X25519AlgorithmIdentifier::create();
    }
}
