<?php

declare(strict_types=1);

namespace FusionAuth\JWTAuth\WebTokenProvider\Providers;

use FusionAuth\JWTAuth\WebTokenProvider\Key\SignerInterface;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use FusionAuth\JWTAuth\WebTokenProvider\Factories;
use FusionAuth\JWTAuth\WebTokenProvider\Providers\JWT\WebTokenProvider;

use function config;

class WebTokenServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->registerAlgorithmManager();
        $this->registerSerializerManager();
        $this->registerSignerInterface();
        $this->registerProvider();
    }

    /**
     * Responsible for providing signing/hashing algorithms
     */
    protected function registerAlgorithmManager(): void
    {
        $this->app->singleton(AlgorithmManager::class, function (Application $app) {
            /** @var string $algo */
            $algo = config('jwt.algo');
            return $app->make(Factories\AlgorithmManagerFactory::class)
                ->make($algo);
        });
    }

    /**
     * JWT representation standard
     */
    protected function registerSerializerManager(): void
    {
        $this->app->singleton(JWSSerializerManager::class, function (): JWSSerializerManager {
            return new JWSSerializerManager([
                new CompactSerializer(),
            ]);
        });
    }

    /**
     * Class that holds private/public/secret/JWKS keys
     */
    protected function registerSignerInterface(): void
    {
        $this->app->singleton(SignerInterface::class, function (Application $app): SignerInterface {
            /** @var string $secret */
            $secret = config('jwt.secret');

            /** @var string $algo */
            $algo = config('jwt.algo');

            /** @var array{jwks?: array{url?: string, cache: array{ttl?: int}}, private: string, passphrase?: string, public: string}|null $keys */
            $keys = config('jwt.keys');

            return $app->make(Factories\SignerFactory::class)
                ->make(
                    $secret,
                    $algo,
                    $keys,
                );
        });
    }

    protected function registerProvider(): void
    {
        /** @var string $algo */
        $algo = config('jwt.algo');

        $this->app->when(WebTokenProvider::class)
            ->needs('$algo')
            ->give($algo);
    }
}
