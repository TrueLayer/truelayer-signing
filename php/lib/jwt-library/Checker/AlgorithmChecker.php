<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Checker;


use function in_array;
use function is_string;

/**
 * AlgorithmChecker class.
 *
 * This class implements the HeaderChecker interface and is responsible for checking the "alg" header in a token.
 */
final class AlgorithmChecker implements HeaderChecker
{
    private const HEADER_NAME = 'alg';

    /**
     * @param string[] $supportedAlgorithms
     */
    public function __construct(
        private array $supportedAlgorithms,
        private bool $protectedHeader = false
    ) {
    }

    public function checkHeader(mixed $value): void
    {
        if (! is_string($value)) {
            throw new InvalidHeaderException('"alg" must be a string.', self::HEADER_NAME, $value);
        }
        if (! in_array($value, $this->supportedAlgorithms, true)) {
            throw new InvalidHeaderException('Unsupported algorithm.', self::HEADER_NAME, $value);
        }
    }

    public function supportedHeader(): string
    {
        return self::HEADER_NAME;
    }

    public function protectedHeaderOnly(): bool
    {
        return $this->protectedHeader;
    }
}
