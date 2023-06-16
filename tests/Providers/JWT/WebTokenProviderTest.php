<?php

declare(strict_types=1);

namespace FusionAuth\JWTAuth\WebTokenProvider\Test\Providers\JWT;

use FusionAuth\JWTAuth\WebTokenProvider\Exceptions\JWKSException;
use FusionAuth\JWTAuth\WebTokenProvider\Factories\AlgorithmManagerFactory;
use FusionAuth\JWTAuth\WebTokenProvider\Factories\SignerFactory;
use FusionAuth\JWTAuth\WebTokenProvider\Providers\JWT\WebTokenProvider;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Providers\JWT\Provider;
use PHPUnit\Framework\TestCase;

/**
 * @covers WebTokenProvider.encode
 * @covers WebTokenProvider.decode
 */
class WebTokenProviderTest extends TestCase
{
    protected readonly AlgorithmManagerFactory $algorithmManagerFactory;

    protected readonly SignerFactory $signerFactory;

    protected readonly string $secret;

    protected string $privateKey = 'file://' . __DIR__ . '/../../id_rsa';

    protected string $publicKey = 'file://' . __DIR__ . '/../../id_rsa.pub';

    protected string $jwksEmpty = 'file://' . __DIR__ . '/../../jwks-empty.json';

    protected string $jwks = 'file://' . __DIR__ . '/../../jwks.json';

    protected function setUp(): void
    {
        $this->testNowTimestamp = time();
        parent::setUp();
    }

    /** @test */
    public function itCanEncodeClaimsUsingASymmetricKey()
    {
        $payload = [
            'sub'          => 1,
            'exp'          => $this->testNowTimestamp + 3600,
            'iat'          => $this->testNowTimestamp,
            'iss'          => '/foo',
            'custom_claim' => 'foobar',
        ];

        $token = $this->getProvider($this->generateSecret(), Provider::ALGO_HS256)->encode($payload);
        [$header, $payload, $signature] = explode('.', $token);

        $claims = json_decode(base64_decode($payload), true);
        $headerValues = json_decode(base64_decode($header), true);

        $this->assertEquals(Provider::ALGO_HS256, $headerValues['alg']);
        $this->assertIsString($signature);

        $this->assertEquals('1', $claims['sub']);
        $this->assertEquals('/foo', $claims['iss']);
        $this->assertEquals('foobar', $claims['custom_claim']);
        $this->assertEquals($exp, $claims['exp']);
        $this->assertEquals($iat, $claims['iat']);
    }

    /** @test */
    public function itCanEncodeAndDecodeATokenUsingASymmetricKey()
    {
        $payload = [
            'sub'          => 1,
            'exp'          => $this->testNowTimestamp + 3600,
            'iat'          => $this->testNowTimestamp,
            'iss'          => '/foo',
            'custom_claim' => 'foobar',
        ];

        $provider = $this->getProvider($this->generateSecret(), Provider::ALGO_HS256);

        $token = $provider->encode($payload);
        $claims = $provider->decode($token);

        $this->assertEquals('1', $claims['sub']);
        $this->assertEquals('/foo', $claims['iss']);
        $this->assertEquals('foobar', $claims['custom_claim']);
        $this->assertEquals($exp, $claims['exp']);
        $this->assertEquals($iat, $claims['iat']);
    }

    /** @test */
    public function itCanEncodeAndDecodeATokenUsingAnAsymmetricRS256Key()
    {
        $payload = [
            'sub'          => 1,
            'exp'          => $this->testNowTimestamp + 3600,
            'iat'          => $this->testNowTimestamp,
            'iss'          => '/foo',
            'custom_claim' => 'foobar',
        ];

        $provider = $this->getProvider(
            null,
            Provider::ALGO_RS256,
            ['private' => $this->privateKey, 'public' => $this->publicKey]
        );

        $token = $provider->encode($payload);

        $header = json_decode(base64_decode(head(explode('.', $token))), true);
        $this->assertEquals(Provider::ALGO_RS256, $header['alg']);

        $claims = $provider->decode($token);

        $this->assertEquals('1', $claims['sub']);
        $this->assertEquals('/foo', $claims['iss']);
        $this->assertEquals('foobar', $claims['custom_claim']);
        $this->assertEquals($exp, $claims['exp']);
        $this->assertEquals($iat, $claims['iat']);
    }

    /** @test */
    public function itShouldThrowAnInvalidExceptionWhenThePayloadCouldNotBeEncoded()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Could not create token:');

        $payload = [
            'sub'          => 1,
            'exp'          => $this->testNowTimestamp + 3600,
            'iat'          => $this->testNowTimestamp,
            'iss'          => '/foo',
            'custom_claim' => 'foobar',
            'invalid_utf8' => "\xB1\x31", // cannot be encoded as JSON
        ];

        $this->getProvider($this->generateSecret(), Provider::ALGO_HS256)->encode($payload);
    }

    /** @test */
    public function itShouldThrowATokenInvalidExceptionWhenTheTokenCouldNotBeDecodedDueToABadSignature()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token Signature could not be verified.');

        // This has a different secret than the one used to encode the token
        $this->getProvider($this->generateSecret(), Provider::ALGO_HS256)
            ->decode(
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwiZXhwIjoxNjQ5MjYxMDY1LCJpYXQiOjE2NDkyNTc0NjUsImlzcyI6Ii9mb28iLCJjdXN0b21fY2xhaW0iOiJmb29iYXIifQ.jamiInQiin-1RUviliPjZxl0MLEnQnVTbr2sGooeXBY'
            );
    }

    /** @test */
    public function itShouldThrowATokenInvalidExceptionWhenTheTokenCouldNotBeDecodedDueToTamperedToken()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token Signature could not be verified.');

        // This sub claim for this token has been tampered with so the signature will not match
        $this->getProvider($this->generateSecret(), Provider::ALGO_HS256)
            ->decode(
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwiZXhwIjoxNjQ5MjYxMDY1LCJpYXQiOjE2NDkyNTc0NjUsImlzcyI6Ii9mb29iYXIiLCJjdXN0b21fY2xhaW0iOiJmb29iYXIifQ.jamiInQiin-1RUviliPjZxl0MLEnQnVTbr2sGooeXBY'
            );
    }

    /** @test */
    public function itShouldThrowATokenInvalidExceptionWhenTheTokenCouldNotBeDecoded()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Could not decode token:');

        $this->getProvider('secret', Provider::ALGO_HS256)->decode('foo.bar.baz');
    }

    /** @test */
    public function itShouldThrowAnExceptionWhenTheAlgorithmPassedIsInvalid()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('The given algorithm could not be found');

        $this->getProvider('secret', 'INVALID_ALGO')->decode('foo.bar.baz');
    }

    /** @test */
    public function itShouldThrowAnExceptionWhenNoSymmetricKeyIsProvidedWhenEncoding()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Secret is not set.');

        $this->getProvider(null, Provider::ALGO_HS256)->encode(['sub' => 1]);
    }

    /** @test */
    public function itShouldThrowAnExceptionWhenNoSymmetricKeyIsProvidedWhenDecoding()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Secret is not set.');

        $this->getProvider(null, Provider::ALGO_HS256)->decode('foo.bar.baz');
    }

    /** @test */
    public function itShouldThrowAnExceptionWhenNoAsymmetricPublicKeyIsProvided()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Public key is not set.');

        $this->getProvider(
            null,
            Provider::ALGO_RS256,
            ['private' => $this->privateKey, 'public' => null]
        )->decode('foo.bar.baz');
    }

    /** @test */
    public function itShouldThrowAnExceptionWhenNoAsymmetricprivateKeyIsProvided()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Private key is not set.');

        $this->getProvider(
            null,
            Provider::ALGO_RS256,
            ['private' => null, 'public' => $this->publicKey]
        )->encode(['sub' => 1]);
    }

    /** @test */
    public function itShouldThrowAnExceptionWhenNoConfigWasProvided()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('You must provide at least a private or public key.');
        $this->getProvider(
            null,
            Provider::ALGO_RS256,
            ['private' => null, 'public' => null]
        )->encode(['sub' => 1]);
    }

    /** @test */
    public function itShouldThrowAnExceptionWhenJwksFileDoesNotExist()
    {
        $this->expectException(JWKSException::class);
        $this->expectExceptionMessage('Cannot retrieve JWKS from');
        $this->getProvider(
            null,
            Provider::ALGO_RS256,
            ['private' => null, 'jwks' => ['url' => 'file://invalid-file']]
        );
    }

    /** @test */
    public function itShouldThrowAnExceptionWhenJwksIsEmpty()
    {
        $this->expectException(JWKSException::class);
        $this->expectExceptionMessage('Cannot retrieve JWKS from');
        $this->getProvider(
            null,
            Provider::ALGO_RS256,
            ['private' => null, 'jwks' => ['url' => $this->jwksEmpty]]
        );
    }

    /** @test */
    public function itCanDecodeATokenUsingJwks()
    {
        // @TODO DataProvider
        $payload = [
            'sub'          => 1,
            'exp'          => $this->testNowTimestamp + 3600,
            'iat'          => $this->testNowTimestamp,
            'iss'          => '/foo',
            'custom_claim' => 'foobar',
        ];

        $provider = $this->getProvider(
            null,
            Provider::ALGO_RS256,
            ['private' => $this->privateKey, 'jwks' => ['url' => $this->jwks]]
        );

        $token = $provider->encode($payload);
        $claims = $provider->decode($token);

        $this->assertEquals('1', $claims['sub']);
        $this->assertEquals('/foo', $claims['iss']);
        $this->assertEquals('foobar', $claims['custom_claim']);
        $this->assertEquals($exp, $claims['exp']);
        $this->assertEquals($iat, $claims['iat']);
    }

    protected function getProvider(?string $secret, string $algo, array $keys = []): WebTokenProvider
    {
        $algorithmManager = $this->getAlgorithmManagerFactory()->make($algo);
        $jwsVerifier = new JWSVerifier($algorithmManager);
        $signer = $this->getSignerFactory()->make($secret, $algo, $keys);

        return new WebTokenProvider(
            $algorithmManager,
            $this->getSerializerManager(),
            $jwsVerifier,
            $signer,
            $algo,
        );
    }

    protected function getAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        if (!isset($this->algorithmManagerFactory)) {
            $this->algorithmManagerFactory = new AlgorithmManagerFactory();
        }
        return $this->algorithmManagerFactory;
    }

    protected function getSignerFactory(): SignerFactory
    {
        if (!isset($this->signerFactory)) {
            $this->signerFactory = new SignerFactory();
        }
        return $this->signerFactory;
    }

    protected function getSerializerManager(): JWSSerializerManager
    {
        if (!isset($this->serializerManager)) {
            $this->serializerManager = new JWSSerializerManager([
                new CompactSerializer(),
            ]);
        }
        return $this->serializerManager;
    }

    protected function generateSecret(): string
    {
        if (!isset($this->secret)) {
            $this->secret = \bin2hex(\random_bytes(32));
        }
        return $this->secret;
    }
}
