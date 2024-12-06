<?php

declare(strict_types=1);

namespace TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive;

use Brick\Math\BigInteger;
use TrueLayer\SpomkyLabs\Pki\ASN1\Component\Identifier;
use TrueLayer\SpomkyLabs\Pki\ASN1\Component\Length;
use TrueLayer\SpomkyLabs\Pki\ASN1\Feature\ElementBase;
use TrueLayer\SpomkyLabs\Pki\ASN1\Util\BigInt;

/**
 * Implements *ENUMERATED* type.
 */
final class Enumerated extends Integer
{
    public static function create(BigInteger|int|string $number): static
    {
        return new static($number, self::TYPE_ENUMERATED);
    }

    protected static function decodeFromDER(Identifier $identifier, string $data, int &$offset): ElementBase
    {
        $idx = $offset;
        $length = Length::expectFromDER($data, $idx)->intLength();
        $bytes = mb_substr($data, $idx, $length, '8bit');
        $idx += $length;
        $num = BigInt::fromSignedOctets($bytes)->getValue();
        $offset = $idx;
        // late static binding since enumerated extends integer type
        return self::create($num);
    }
}
