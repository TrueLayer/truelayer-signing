<?php

declare(strict_types=1);

namespace TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive;

use TrueLayer\SpomkyLabs\Pki\ASN1\Type\PrimitiveString;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\UniversalClass;

/**
 * Implements *NumericString* type.
 */
final class NumericString extends PrimitiveString
{
    use UniversalClass;

    private function __construct(string $string)
    {
        parent::__construct(self::TYPE_NUMERIC_STRING, $string);
    }

    public static function create(string $string): self
    {
        return new self($string);
    }

    protected function validateString(string $string): bool
    {
        return preg_match('/[^\d ]/', $string) !== 1;
    }
}
