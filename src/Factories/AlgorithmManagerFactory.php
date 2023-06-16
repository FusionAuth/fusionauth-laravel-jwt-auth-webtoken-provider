<?php

declare(strict_types=1);

namespace FusionAuth\JWTAuth\WebTokenProvider\Factories;

use Jose\Component\Core\Algorithm as AlgorithmContract;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Providers\JWT\Provider;

class AlgorithmManagerFactory
{
    /**
     * @var AlgorithmContract[]
     */
    private array $pool = [];

    /**
     * Creates a new AlgorithmManager instance with the provided algorithm in `jwt.algo` config
     *
     * @param string $algo
     *
     * @return \Jose\Component\Core\AlgorithmManager
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function make(string $algo): AlgorithmManager
    {
        return new AlgorithmManager([
            $this->buildAlgorithm($algo)
        ]);
    }

    /**
     * @param string $algo Friendly name for the algorithm (e.g. HS256)
     *
     * @return \Jose\Component\Core\Algorithm
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    protected function buildAlgorithm(string $algo): AlgorithmContract
    {
        return $this->build(
            match ($algo) {
                Provider::ALGO_HS256 => Algorithm\HS256::class,
                Provider::ALGO_HS384 => Algorithm\HS384::class,
                Provider::ALGO_HS512 => Algorithm\HS512::class,
                Provider::ALGO_RS256 => Algorithm\RS256::class,
                Provider::ALGO_RS384 => Algorithm\RS384::class,
                Provider::ALGO_RS512 => Algorithm\RS512::class,
                Provider::ALGO_ES256 => Algorithm\ES256::class,
                Provider::ALGO_ES384 => Algorithm\ES384::class,
                Provider::ALGO_ES512 => Algorithm\ES512::class,
                default => throw new JWTException('The given algorithm could not be found'),
            }
        );
    }

    /**
     * @param string $algo
     *
     * @return \Jose\Component\Core\Algorithm
     */
    private function build(string $algo): AlgorithmContract
    {
        if (!isset($this->pool[$algo])) {
            $this->pool[$algo] = new $algo();
        }
        return $this->pool[$algo];
    }
}
