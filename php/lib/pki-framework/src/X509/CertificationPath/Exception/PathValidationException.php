<?php

declare(strict_types=1);

namespace TrueLayer\SpomkyLabs\Pki\X509\CertificationPath\Exception;

use TrueLayer\SpomkyLabs\Pki\X509\Exception\X509ValidationException;

/**
 * Exception thrown on certification path validation errors.
 */
final class PathValidationException extends X509ValidationException
{
}
