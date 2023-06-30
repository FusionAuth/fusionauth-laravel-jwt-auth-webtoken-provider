# PHP JWT Framework for Laravel

[![Integration](https://github.com/vcampitelli/fusionauth-laravel-jwt-auth-webtoken-provider/actions/workflows/integration.yml/badge.svg)](https://github.com/vcampitelli/fusionauth-laravel-jwt-auth-webtoken-provider/actions/workflows/integration.yml)

This library adds support to [`web-token/jwt-framework`](https://github.com/web-token/jwt-framework) as an alternative to [`lcobucci/jwt`](https://github.com/lcobucci/jwt) in [`tymon/jwt-auth`](https://github.com/tymondesigns/jwt-auth), which is probably the most used Laravel package for JWT authentication.

The main goal here is to provide [JWKS support](https://datatracker.ietf.org/doc/html/rfc7517) instead of using public keys stored locally.

## Installation

You can install this library via [Composer](https://getcomposer.org).

```shell
composer require fusionauth/jwt-auth-webtoken-provider
```

Then, you should add one of [PHP JWT Framework's Signature libraries](https://web-token.spomky-labs.com/the-components/signed-tokens-jws/signature-algorithms) according to the algorithm you want to use:

- HMAC algorithms (`HS256`, `HS384` or `HS512`):
    ```shell
    composer require web-token/jwt-signature-algorithm-hmac
    ```
- RSASSA-PKCS1 v1_5 algorithms (`RS256`, `RS384` or `RS512`):
    ```shell
    composer require web-token/jwt-signature-algorithm-rsa
    ```
- ECDSA algorithms (`ES256`, `ES384` or `ES512`):
    ```shell
    composer require web-token/jwt-signature-algorithm-ecdsa
    ```

## Usage

This requires composer 2.2 or greater.

Publish this package config file (which overrides [the one from `tymon/jwt-auth`](https://jwt-auth.readthedocs.io/en/develop/laravel-installation/#publish-the-config)):

```shell
php artisan vendor:publish --provider="FusionAuth\JWTAuth\WebTokenProvider\Providers\WebTokenServiceProvider"
```

### Using JWKS

Instead of providing a local public key and use [JWKS](https://datatracker.ietf.org/doc/html/rfc7517), edit your `.env` file to add these lines:

```dotenv
JWT_JWKS_URL=https://your.application.address.to/jwks.json
JWT_JWKS_URL_CACHE=86400
```

## Questions and support

If you have a question or support issue regarding this client library, we'd love to hear from you.

If you have a paid edition with support included, please [open a ticket in your account portal](https://account.fusionauth.io/account/support/). Learn more about [paid editions here](https://fusionauth.io/pricing).

Otherwise, please [post your question in the community forum](https://fusionauth.io/community/forum/).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/FusionAuth/fusionauth-laravel-jwt-auth-webtoken-provider.

## License

This code is available as open source under the terms of the [Apache v2.0 License](https://opensource.org/licenses/Apache-2.0).

