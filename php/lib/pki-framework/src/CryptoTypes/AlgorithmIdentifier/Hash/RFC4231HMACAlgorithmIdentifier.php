<?php

declare(strict_types=1);

namespace TrueLayer\SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash;

use TrueLayer\SpomkyLabs\Pki\ASN1\Element;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use TrueLayer\SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\HashAlgorithmIdentifier;
use TrueLayer\SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\PRFAlgorithmIdentifier;
use TrueLayer\SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

/**
 * Base class for HMAC algorithm identifiers specified in RFC 4231.
 *
 * @see https://tools.ietf.org/html/rfc4231#section-3.1
 */
abstract class RFC4231HMACAlgorithmIdentifier extends SpecificAlgorithmIdentifier implements HashAlgorithmIdentifier, PRFAlgorithmIdentifier
{
    /**
     * @param Element|null $params Parameters stored for re-encoding.
     */
    protected function __construct(
        string $oid,
        protected ?Element $params
    ) {
        parent::__construct($oid);
    }

    /**
     * @return null|NullType
     */
    protected function paramsASN1(): ?Element
    {
        return $this->params;
    }
}
