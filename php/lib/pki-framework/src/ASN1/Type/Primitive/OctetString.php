<?php

declare(strict_types=1);

namespace TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive;

use TrueLayer\SpomkyLabs\Pki\ASN1\Type\PrimitiveString;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\UniversalClass;

/**
 * Implements *OCTET STRING* type.
 */
final class OctetString extends PrimitiveString
{
    use UniversalClass;

    private function __construct(string $string)
    {
        parent::__construct(self::TYPE_OCTET_STRING, $string);
    }

    public static function create(string $string): self
    {
        return new self($string);
    }
}
