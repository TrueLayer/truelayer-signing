<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Signature;

use InvalidArgumentException;
use TrueLayer\Jose\Component\Checker\TokenTypeSupport;
use TrueLayer\Jose\Component\Core\JWT;


final class JWSTokenSupport implements TokenTypeSupport
{
    public function supports(JWT $jwt): bool
    {
        return $jwt instanceof JWS;
    }

    /**
     * @param array<string, mixed> $protectedHeader
     * @param array<string, mixed> $unprotectedHeader
     */
    public function retrieveTokenHeaders(JWT $jwt, int $index, array &$protectedHeader, array &$unprotectedHeader): void
    {
        if (! $jwt instanceof JWS) {
            return;
        }

        if ($index > $jwt->countSignatures()) {
            throw new InvalidArgumentException('Unknown signature index.');
        }
        $protectedHeader = $jwt->getSignature($index)
            ->getProtectedHeader();
        $unprotectedHeader = $jwt->getSignature($index)
            ->getHeader();
    }
}
