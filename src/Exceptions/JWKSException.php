<?php

declare(strict_types=1);

namespace FusionAuth\JWTAuth\WebTokenProvider\Exceptions;

use Exception;
use Throwable;

class JWKSException extends Exception
{
    public function __construct(string $message = '', int $code = 0, Throwable $previous = null)
    {
        parent::__construct(
            $message ?: 'Invalid JWKS provided',
            $code,
            $previous
        );
    }
}
