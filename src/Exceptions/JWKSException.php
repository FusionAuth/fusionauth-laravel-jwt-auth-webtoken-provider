<?php

declare(strict_types=1);

namespace FusionAuth\JWTAuth\WebTokenProvider\Exceptions;

use Exception;

class JWKSException extends Exception
{
    protected $message = 'Invalid JWKS provided';
}
