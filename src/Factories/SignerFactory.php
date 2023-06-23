<?php

declare(strict_types=1);

namespace FusionAuth\JWTAuth\WebTokenProvider\Factories;

use FusionAuth\JWTAuth\WebTokenProvider\Key\AsymmetricSigner;
use FusionAuth\JWTAuth\WebTokenProvider\Key\JWKSSigner;
use FusionAuth\JWTAuth\WebTokenProvider\Key\SignerInterface;
use FusionAuth\JWTAuth\WebTokenProvider\Key\SymmetricSigner;
use Tymon\JWTAuth\Exceptions\JWTException;

class SignerFactory
{
    /**
     * @param string|null $secret
     * @param string      $algo
     * @param array{
     *     jwks?: array{url?: string, cache: array{ttl?: int}},
     *     private: string,
     *     passphrase?: string,
     *     public: string
     * }|null $keys
     *
     * @return \FusionAuth\JWTAuth\WebTokenProvider\Key\SignerInterface
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function make(?string $secret, string $algo, ?array $keys): SignerInterface
    {
        // SymmetricSigner
        if (\str_starts_with($algo, 'HS')) {
            return new SymmetricSigner((string) $secret);
        }

        // Loading JWKS keys
        if ((!empty($keys['jwks'])) && (!empty($keys['jwks']['url']))) {
            return new JWKSSigner(
                (string) $keys['private'],
                $keys['passphrase'] ?? null,
                $keys['jwks']['url'],
                (int) ($keys['jwks']['cache']['ttl'] ?? 86400),
            );
        }

        // For asymmetric signers, we need to have at least one of these keys
        if ((empty($keys['private'])) && (empty($keys['public']))) {
            throw new JWTException('You must provide at least a private or public key.');
        }
        return new AsymmetricSigner(
            (string) $keys['private'],
            $keys['passphrase'] ?? null,
            (string) $keys['public'],
        );
    }
}
