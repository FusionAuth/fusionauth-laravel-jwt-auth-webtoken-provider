<?php

namespace FusionAuth\JWTAuth\WebTokenProvider\Providers\JWT;

use FusionAuth\JWTAuth\WebTokenProvider\Key\SignerInterface;
use FusionAuth\JWTAuth\WebTokenProvider\Key\SymmetricSigner;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Tymon\JWTAuth\Contracts\Providers\JWT;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class WebTokenProvider implements JWT
{
    /**
     * @param \Jose\Component\Core\AlgorithmManager                     $algorithmManager
     * @param \Jose\Component\Signature\Serializer\JWSSerializerManager $serializerManager
     * @param \Jose\Component\Signature\JWSVerifier                     $jwsVerifier
     * @param \FusionAuth\JWTAuth\WebTokenProvider\Key\SignerInterface  $signer
     * @param string                                                    $algo
     */
    public function __construct(
        protected readonly AlgorithmManager $algorithmManager,
        protected readonly JWSSerializerManager $serializerManager,
        protected readonly JWSVerifier $jwsVerifier,
        protected readonly SignerInterface $signer,
        protected readonly string $algo,
    ) {
    }

    /**
     * @param array $payload
     *
     * @return string
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function encode(array $payload): string
    {
        $signingKey = $this->signer->getSigningKey();
        if (!isset($signingKey)) {
            throw new JWTException(
                ($this->signer instanceof SymmetricSigner)
                    ? 'Secret is not set.'
                    : 'Private key is not set.'
            );
        }

        $payload = json_encode($payload);
        if ($payload === false) {
            throw new JWTException('Could not create token: ' . \json_last_error_msg());
        }

        $jws = $this->getJwsBuilder()
            ->create()
            ->withPayload($payload)
            ->addSignature($signingKey, ['alg' => $this->algo])
            ->build();

        foreach ($this->serializerManager->list() as $name) {
            try {
                return $this->serializerManager->serialize($name, $jws, 0);
            } catch (\Throwable) {
                // continue...
            }
        }

        throw new JWTException('No JWT serializer provided');
    }

    /**
     * @param string $token
     *
     * @return array
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     * @throws \Tymon\JWTAuth\Exceptions\TokenInvalidException
     */
    public function decode($token): array
    {
        $jwks = $this->signer->getVerificationKeys();
        if ((!isset($jwks)) || (!$jwks->count())) {
            throw new JWTException(
                ($this->signer instanceof SymmetricSigner)
                    ? 'Secret is not set.'
                    : 'Public key is not set.'
            );
        }

        // Instead of using JWSLoader, we do the process manually to throw custom exceptions

        try {
            $jws = $this->serializerManager->unserialize($token);
        } catch (\Throwable $t) {
            throw new TokenInvalidException('Could not decode token: ' . $t->getMessage(), $t->getCode(), $t);
        }

        if (!$this->jwsVerifier->verifyWithKeySet($jws, $jwks, 0)) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        try {
            return json_decode($jws->getPayload(), true);
        } catch (\Throwable $t) {
            throw new TokenInvalidException('Could not decode token: ' . $t->getMessage(), $t->getCode(), $t);
        }
    }

    protected function getJwsBuilder(): JWSBuilder
    {
        if (!isset($this->jwsBuilder)) {
            $this->jwsBuilder = new JWSBuilder($this->algorithmManager);
        }
        return $this->jwsBuilder;
    }
}
