# PHP JWT Framework for Laravel

This library adds [web-token/jwt-framework](https://github.com/web-token/jwt-framework) as an alternative to [lcobucci/jwt](https://github.com/lcobucci/jwt) in [tymon/jwt-auth](https://github.com/tymondesigns/jwt-auth) for Laravel in order to provide [JWKS support](https://datatracker.ietf.org/doc/html/rfc7517).

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

After [publishing the config file](https://jwt-auth.readthedocs.io/en/develop/laravel-installation/#publish-the-config) from `tymon/jwt-auth`, change the `providers.jwt` to [`WebTokenProvider`](./src/Providers/WebTokenServiceProvider.php):

```php
'jwt' => FusionAuth\JWTAuth\WebTokenProvider\Providers\JWT\WebTokenProvider::class,
```

### Using JWKS

Instead of providing a local public key and using [JWKS](https://datatracker.ietf.org/doc/html/rfc7517), change your [`config/jwt.php` file](https://jwt-auth.readthedocs.io/en/develop/configuration/) again to add a new `jwks` section inside your `keys`:

```php
    'keys' => [
        /**
          * Leave `private` and `passphrase` as they are and add this:
          */
        
        'jwks' => [
            'url' => env('JWT_JWKS_URL'),
            'cache' => [
                'ttl' => env('JWT_JWKS_URL_CACHE'),
            ],
        ],
    ],
```

Now edit your `.env` file to add the JWKS config:

```dotenv
JWT_JWKS_URL=https://your.application.address.to/jwks.json
JWT_JWKS_URL_CACHE=86400
```

## Questions and support

If you have a question or support issue regarding this client library, we'd love to hear from you.

If you have a paid edition with support included, please [open a ticket in your account portal](https://account.fusionauth.io/account/support/). Learn more about [paid editions here](https://fusionauth.io/pricing).

Otherwise, please [post your question in the community forum](https://fusionauth.io/community/forum/).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/FusionAuth/fusionauth-php-client.

## License

This code is available as open source under the terms of the [Apache v2.0 License](https://opensource.org/licenses/Apache-2.0).

