<?php

declare(strict_types=1);

namespace FusionAuth\JWTAuth\WebTokenProvider\Key;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;

class AsymmetricSigner implements SignerInterface
{
    private readonly ?JWK $privateKey;

    private readonly ?JWKSet $publicKey;

    /**
     * @param string      $privateKey
     * @param string|null $passphrase
     * @param string      $publicKey
     */
    public function __construct(string $privateKey, ?string $passphrase, string $publicKey)
    {
        $this->privateKey = $this->loadSigningKey($privateKey, $passphrase);
        $this->publicKey = $this->loadVerificationKeys($publicKey);
    }

    protected function loadSigningKey(string $privateKey, ?string $passphrase): ?JWK
    {
        $privateKey = \str_replace('file://', '', $privateKey);
        if (empty($privateKey)) {
            return null;
        }
        return JWKFactory::createFromKeyFile($privateKey, $passphrase);
    }

    protected function loadVerificationKeys(string $publicKey): ?JWKSet
    {
        if (empty($publicKey)) {
            return null;
        }
        return new JWKSet([
            JWKFactory::createFromKeyFile($publicKey),
        ]);
    }

    public function getSigningKey(): ?JWK
    {
        return $this->privateKey;
    }

    public function getVerificationKeys(): ?JWKSet
    {
        return $this->publicKey;
    }
}
