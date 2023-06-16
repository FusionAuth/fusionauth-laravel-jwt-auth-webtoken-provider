<?php

declare(strict_types=1);

namespace FusionAuth\JWTAuth\WebTokenProvider\Key;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Tymon\JWTAuth\Exceptions\JWTException;

class SymmetricSigner implements SignerInterface
{
    private readonly JWK $jwk;
    private readonly JWKSet $jwks;

    /**
     * @param string $secret
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function __construct(string $secret)
    {
        if (empty($secret)) {
            throw new JWTException('Secret is not set.');
        }
        $this->jwk = JWKFactory::createFromSecret($secret);
        $this->jwks = new JWKSet([$this->jwk]);
    }

    public function getSigningKey(): ?JWK
    {
        return $this->jwk;
    }

    public function getVerificationKeys(): ?JWKSet
    {
        return $this->jwks;
    }
}
