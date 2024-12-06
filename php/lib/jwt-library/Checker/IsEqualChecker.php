<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Checker;



/**
 * This class implements a claim and header checker that checks if the value is equal to the expected value.
 * @see \Truelayer\Jose\Tests\Component\Checker\IsEqualCheckerTest
 */
final class IsEqualChecker implements ClaimChecker, HeaderChecker
{
    /**
     * @param string $key                 The claim or header parameter name to check.
     * @param bool   $protectedHeaderOnly [optional] Whether the header parameter MUST be protected.
     *                                    This option has no effect for claim checkers.
     */
    public function __construct(
        private string $key,
        private mixed $value,
        private bool $protectedHeaderOnly = true
    ) {
    }

    public function checkClaim(mixed $value): void
    {
        if ($value !== $this->value) {
            throw new InvalidClaimException(sprintf('The "%s" claim is invalid.', $this->key), $this->key, $value);
        }
    }

    public function supportedClaim(): string
    {
        return $this->key;
    }

    public function checkHeader(mixed $value): void
    {
        if ($value !== $this->value) {
            throw new InvalidHeaderException(sprintf('The "%s" header is invalid.', $this->key), $this->key, $value);
        }
    }

    public function supportedHeader(): string
    {
        return $this->key;
    }

    public function protectedHeaderOnly(): bool
    {
        return $this->protectedHeaderOnly;
    }
}
