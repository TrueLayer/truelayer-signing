<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Checker;

use Exception;

/**
 * This exception is thrown by claim checkers when a mandatory claim is missing.
 */
class MissingMandatoryClaimException extends Exception implements ClaimExceptionInterface
{
    /**
     * MissingMandatoryClaimException constructor.
     *
     * @param string[] $claims
     */
    public function __construct(
        string $message,
        private readonly array $claims
    ) {
        parent::__construct($message);
    }

    /**
     * @return string[]
     */
    public function getClaims(): array
    {
        return $this->claims;
    }
}
