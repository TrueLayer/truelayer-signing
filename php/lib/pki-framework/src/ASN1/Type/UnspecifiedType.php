<?php

declare(strict_types=1);

namespace TrueLayer\SpomkyLabs\Pki\ASN1\Type;

use TrueLayer\SpomkyLabs\Pki\ASN1\Component\Identifier;
use TrueLayer\SpomkyLabs\Pki\ASN1\Element;
use TrueLayer\SpomkyLabs\Pki\ASN1\Feature\ElementBase;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Constructed\ConstructedString;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Constructed\Set;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\BMPString;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\CharacterString;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\Enumerated;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\GeneralizedTime;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\GeneralString;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\GraphicString;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\IA5String;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\NumericString;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectDescriptor;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\PrintableString;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\Real;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\RelativeOID;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\T61String;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\UniversalString;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\UTCTime;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\UTF8String;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\VideotexString;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Primitive\VisibleString;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Tagged\ApplicationType;
use TrueLayer\SpomkyLabs\Pki\ASN1\Type\Tagged\PrivateType;
use UnexpectedValueException;

/**
 * Decorator class to wrap an element without already knowing the specific underlying type.
 *
 * Provides accessor methods to test the underlying type and return a type hinted instance of the concrete element.
 * @see \SpomkyLabs\Pki\Test\ASN1\Type\UnspecifiedTypeTest
 */
final class UnspecifiedType implements ElementBase
{
    private function __construct(
        private readonly Element $element
    ) {
    }

    public static function create(Element $element): self
    {
        return new self($element);
    }

    /**
     * Initialize from DER data.
     *
     * @param string $data DER encoded data
     */
    public static function fromDER(string $data): self
    {
        return Element::fromDER($data)->asUnspecified();
    }

    /**
     * Initialize from `ElementBase` interface.
     */
    public static function fromElementBase(ElementBase $el): self
    {
        // if element is already wrapped
        if ($el instanceof self) {
            return $el;
        }
        return self::create($el->asElement());
    }

    /**
     * Get the wrapped element as a context specific tagged type.
     */
    public function asTagged(): TaggedType
    {
        if (! $this->element instanceof TaggedType) {
            throw new UnexpectedValueException('Tagged element expected, got ' . $this->typeDescriptorString());
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as an application specific type.
     */
    public function asApplication(): ApplicationType
    {
        if (! $this->element instanceof ApplicationType) {
            throw new UnexpectedValueException('Application type expected, got ' . $this->typeDescriptorString());
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a private tagged type.
     */
    public function asPrivate(): PrivateType
    {
        if (! $this->element instanceof PrivateType) {
            throw new UnexpectedValueException('Private type expected, got ' . $this->typeDescriptorString());
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a boolean type.
     */
    public function asBoolean(): Boolean
    {
        if (! $this->element instanceof Boolean) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_BOOLEAN));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as an integer type.
     */
    public function asInteger(): Integer
    {
        if (! $this->element instanceof Integer) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_INTEGER));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a bit string type.
     */
    public function asBitString(): BitString
    {
        if (! $this->element instanceof BitString) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_BIT_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as an octet string type.
     */
    public function asOctetString(): OctetString
    {
        if (! $this->element instanceof OctetString) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_OCTET_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a null type.
     */
    public function asNull(): NullType
    {
        if (! $this->element instanceof NullType) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_NULL));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as an object identifier type.
     */
    public function asObjectIdentifier(): ObjectIdentifier
    {
        if (! $this->element instanceof ObjectIdentifier) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_OBJECT_IDENTIFIER));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as an object descriptor type.
     */
    public function asObjectDescriptor(): ObjectDescriptor
    {
        if (! $this->element instanceof ObjectDescriptor) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_OBJECT_DESCRIPTOR));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a real type.
     */
    public function asReal(): Real
    {
        if (! $this->element instanceof Real) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_REAL));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as an enumerated type.
     */
    public function asEnumerated(): Enumerated
    {
        if (! $this->element instanceof Enumerated) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_ENUMERATED));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a UTF8 string type.
     */
    public function asUTF8String(): UTF8String
    {
        if (! $this->element instanceof UTF8String) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_UTF8_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a relative OID type.
     */
    public function asRelativeOID(): RelativeOID
    {
        if (! $this->element instanceof RelativeOID) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_RELATIVE_OID));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a sequence type.
     */
    public function asSequence(): Sequence
    {
        if (! $this->element instanceof Sequence) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_SEQUENCE));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a set type.
     */
    public function asSet(): Set
    {
        if (! $this->element instanceof Set) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_SET));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a numeric string type.
     */
    public function asNumericString(): NumericString
    {
        if (! $this->element instanceof NumericString) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_NUMERIC_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a printable string type.
     */
    public function asPrintableString(): PrintableString
    {
        if (! $this->element instanceof PrintableString) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_PRINTABLE_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a T61 string type.
     */
    public function asT61String(): T61String
    {
        if (! $this->element instanceof T61String) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_T61_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a videotex string type.
     */
    public function asVideotexString(): VideotexString
    {
        if (! $this->element instanceof VideotexString) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_VIDEOTEX_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a IA5 string type.
     */
    public function asIA5String(): IA5String
    {
        if (! $this->element instanceof IA5String) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_IA5_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as an UTC time type.
     */
    public function asUTCTime(): UTCTime
    {
        if (! $this->element instanceof UTCTime) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_UTC_TIME));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a generalized time type.
     */
    public function asGeneralizedTime(): GeneralizedTime
    {
        if (! $this->element instanceof GeneralizedTime) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_GENERALIZED_TIME));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a graphic string type.
     */
    public function asGraphicString(): GraphicString
    {
        if (! $this->element instanceof GraphicString) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_GRAPHIC_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a visible string type.
     */
    public function asVisibleString(): VisibleString
    {
        if (! $this->element instanceof VisibleString) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_VISIBLE_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a general string type.
     */
    public function asGeneralString(): GeneralString
    {
        if (! $this->element instanceof GeneralString) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_GENERAL_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a universal string type.
     */
    public function asUniversalString(): UniversalString
    {
        if (! $this->element instanceof UniversalString) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_UNIVERSAL_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a character string type.
     */
    public function asCharacterString(): CharacterString
    {
        if (! $this->element instanceof CharacterString) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_CHARACTER_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a BMP string type.
     */
    public function asBMPString(): BMPString
    {
        if (! $this->element instanceof BMPString) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_BMP_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as a constructed string type.
     */
    public function asConstructedString(): ConstructedString
    {
        if (! $this->element instanceof ConstructedString) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_CONSTRUCTED_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as any string type.
     */
    public function asString(): StringType
    {
        if (! $this->element instanceof StringType) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_STRING));
        }
        return $this->element;
    }

    /**
     * Get the wrapped element as any time type.
     */
    public function asTime(): TimeType
    {
        if (! $this->element instanceof TimeType) {
            throw new UnexpectedValueException($this->generateExceptionMessage(Element::TYPE_TIME));
        }
        return $this->element;
    }

    public function asElement(): Element
    {
        return $this->element;
    }

    public function asUnspecified(): self
    {
        return $this;
    }

    public function toDER(): string
    {
        return $this->element->toDER();
    }

    public function typeClass(): int
    {
        return $this->element->typeClass();
    }

    public function tag(): int
    {
        return $this->element->tag();
    }

    public function isConstructed(): bool
    {
        return $this->element->isConstructed();
    }

    public function isType(int $tag): bool
    {
        return $this->element->isType($tag);
    }

    public function isTagged(): bool
    {
        return $this->element->isTagged();
    }

    /**
     * {@inheritdoc}
     *
     * Consider using any of the `as*` accessor methods instead.
     */
    public function expectType(int $tag): ElementBase
    {
        return $this->element->expectType($tag);
    }

    /**
     * {@inheritdoc}
     *
     * Consider using `asTagged()` method instead and chaining
     * with `TaggedType::asExplicit()` or `TaggedType::asImplicit()`.
     */
    public function expectTagged(?int $tag = null): TaggedType
    {
        return $this->element->expectTagged($tag);
    }

    /**
     * Generate message for exceptions thrown by `as*` methods.
     *
     * @param int $tag Type tag of the expected element
     */
    private function generateExceptionMessage(int $tag): string
    {
        return sprintf('%s expected, got %s.', Element::tagToName($tag), $this->typeDescriptorString());
    }

    /**
     * Get textual description of the wrapped element for debugging purposes.
     */
    private function typeDescriptorString(): string
    {
        $type_cls = $this->element->typeClass();
        $tag = $this->element->tag();
        $str = $this->element->isConstructed() ? 'constructed ' : 'primitive ';
        if ($type_cls === Identifier::CLASS_UNIVERSAL) {
            $str .= Element::tagToName($tag);
        } else {
            $str .= Identifier::classToName($type_cls) . " TAG {$tag}";
        }
        return $str;
    }
}
