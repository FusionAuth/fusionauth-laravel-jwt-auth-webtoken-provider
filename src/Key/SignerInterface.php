<?php

declare(strict_types=1);

namespace FusionAuth\JWTAuth\WebTokenProvider\Key;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

interface SignerInterface
{
    /**
     * Returns key to encode tokens
     *
     * @return \Jose\Component\Core\JWK|null
     */
    public function getSigningKey(): ?JWK;

    /**
     * Returns keys to decode tokens
     *
     * @return \Jose\Component\Core\JWKSet|null
     */
    public function getVerificationKeys(): ?JWKSet;
}
