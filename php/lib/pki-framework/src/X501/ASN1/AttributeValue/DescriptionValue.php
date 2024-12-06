<?php

declare(strict_types=1);

namespace TrueLayer\SpomkyLabs\Pki\X501\ASN1\AttributeValue;

use TrueLayer\SpomkyLabs\Pki\X501\ASN1\AttributeType;
use TrueLayer\SpomkyLabs\Pki\X501\ASN1\AttributeValue\Feature\DirectoryString;

/**
 * 'description' attribute value.
 *
 * @see https://www.itu.int/ITU-T/formal-language/itu-t/x/x520/2012/SelectedAttributeTypes.html#SelectedAttributeTypes.description
 */
final class DescriptionValue extends DirectoryString
{
    public static function create(string $value, int $string_tag = DirectoryString::UTF8): static
    {
        return new static(AttributeType::OID_DESCRIPTION, $value, $string_tag);
    }
}
