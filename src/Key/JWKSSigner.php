<?php

declare(strict_types=1);

namespace FusionAuth\JWTAuth\WebTokenProvider\Key;

use FusionAuth\JWTAuth\WebTokenProvider\Exceptions\JWKSException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Jose\Component\Core\JWKSet;

class JWKSSigner extends AsymmetricSigner implements SignerInterface
{
    /**
     * @param string      $privateKey
     * @param string|null $passphrase
     * @param string      $jwksUrl
     * @param int         $jwksCacheTtl
     */
    public function __construct(
        string $privateKey,
        ?string $passphrase,
        string $jwksUrl,
        private readonly int $jwksCacheTtl
    ) {
        parent::__construct($privateKey, $passphrase, $jwksUrl);
    }

    /**
     * @param string $publicKey
     *
     * @return \Jose\Component\Core\JWKSet|null
     * @throws \FusionAuth\JWTAuth\WebTokenProvider\Exceptions\JWKSException
     */
    protected function loadVerificationKeys(string $publicKey): ?JWKSet
    {
        if (empty($publicKey)) {
            return null;
        }

        $json = $this->loadJson($publicKey, $this->jwksCacheTtl);
        if (empty($json)) {
            throw new JWKSException("Cannot retrieve JWKS from {$publicKey}");
        }

        try {
            return JWKSet::createFromJson($json);
        } catch (\JsonException $e) {
            throw new JWKSException(
                "Cannot retrieve JWKS from {$publicKey}: " . $e->getMessage(),
                $e->getCode(),
                $e
            );
        }
    }

    /**
     * Returns a JSON from the specified URL
     *
     * @param string $url
     * @param int    $ttl
     *
     * @return string|null
     */
    protected function loadJson(string $url, int $ttl): ?string
    {
        // Local file
        if (\str_starts_with($url, 'file://')) {
            $file = \substr($url, 7);
            if (!\is_readable($file)) {
                return null;
            }
            return \file_get_contents($file) ?: null;
        }

        // Downloading remote file and caching it
        return Cache::remember(
            'jose.jwks',
            $ttl,
            fn() => Http::get($url)->body(),
        );
    }
}
