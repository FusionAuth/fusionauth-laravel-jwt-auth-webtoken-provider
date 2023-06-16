<?php

declare(strict_types=1);

namespace FusionAuth\JWTAuth\WebTokenProvider\Providers;

use FusionAuth\JWTAuth\WebTokenProvider\Key\SignerInterface;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use FusionAuth\JWTAuth\WebTokenProvider\Factories;
use FusionAuth\JWTAuth\WebTokenProvider\Providers\JWT\WebTokenProvider;

use function config;

class WebTokenServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Responsible for providing signing/hashing algorithms
        $this->app->singleton(AlgorithmManager::class, function (Application $app) {
            return $app->make(Factories\AlgorithmManagerFactory::class)
                ->make(config('jwt.algo'));
        });

        // JWT representation standard
        $this->app->singleton(JWSSerializerManager::class, function (): JWSSerializerManager {
            return new JWSSerializerManager([
                new CompactSerializer(),
            ]);
        });

        // Class that holds private/public/secret/JWKS keys
        $this->app->singleton(SignerInterface::class, function (Application $app): SignerInterface {
            return $app->make(Factories\SignerFactory::class)
                ->make(
                    config('jwt.secret'),
                    config('jwt.algo'),
                    config('jwt.keys'),
                );
        });

        $this->app->when(WebTokenProvider::class)
            ->needs('$algo')
            ->give(config('jwt.algo'));
    }
}
