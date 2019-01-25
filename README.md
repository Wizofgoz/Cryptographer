# Cryptographer
<p>
<a href="https://travis-ci.org/Wizofgoz/Cryptographer"><img src="https://travis-ci.org/Wizofgoz/Cryptographer.svg?branch=master" alt="Build Status"></a>
<a href="https://github.styleci.io/repos/167452628"><img src="https://github.styleci.io/repos/167452628/shield?branch=master" alt="Style Status"></a>
<a href="https://packagist.org/packages/wizofgoz/cryptographer"><img src="https://poser.pugx.org/wizofgoz/cryptographer/downloads" alt="Total Downloads"></a>
<a href="https://packagist.org/packages/wizofgoz/cryptographer"><img src="https://poser.pugx.org/wizofgoz/cryptographer/v/stable.svg" alt="Latest Stable Version"></a>
<a href="https://packagist.org/packages/wizofgoz/cryptographer"><img src="https://poser.pugx.org/wizofgoz/cryptographer/license.svg" alt="License"></a>
</p>

## Introduction
Cryptographer provides an extensible replacement for Laravel's encryption service. It also allows you to define multiple drivers that can be used for different areas of your application.

## Installation
You may use Composer to install Cryptographer into your Laravel project:

`composer require wizofgoz/cryptographer`

After installing, publish the configuration:

`php artisan vendor:publish --provider="Wizofgoz\Cryptographer\EncryptionServiceProvider"`

## Configuration
After publishing the configuration file, it will be located at `config/cryptographer.php` This file allows you to define the encryption drivers available to your application.

### Default Driver
This option allows you to define the default driver to use when using the encryption service. If no default driver is set, the first entry in the drivers array will be used.

`'default' => 'default'`

### Available Drivers
This option allows for defining the encryption drivers available to your application. Each entry in the list MUST contain a schema, cipher, and key for proper use.

```php
'drivers' => [
    'default' => [
        'schema' => 'openssl',
        'cipher' => OpenSslSchema::CIPHER_AES_128,
        'key'    => env('APP_KEY'),
    ],
],
```
## Available Schemas
### OpenSSL
The `openssl` schema is drop-in replacement for Laravel's encryption system that will work with existing keys assuming the cipher is set correctly.

#### Supported Ciphers

- `OpenSslSchema::CIPHER_AES_128`: AES-128-CBC - default
- `OpenSslSchema::CIPHER_AES_256`: AES-256-CBC

### Sodium
The `sodium` schema depends on the [Sodium](http://php.net/manual/en/book.sodium.php) PHP extension and will not be available if it is missing. In PHP 7.2+, the Sodium extension is part of the core and should always be available.

#### Supported Ciphers

- `SodiumSchema::CIPHER_AES_256`: AES-256-GCM - requires hardware support
- `SodiumSchema::CIPHER_CHACHA`: CHACHA-20-POLY-1305
- `SodiumSchema::CIPHER_CHACHA_IETF`: CHACHA-20-POLY-1305-IETF
- `SodiumSchema::CIPHER_X_CHACHA_IETF`: CHACHA-20-POLY-1305-IETF - default

## Usage
This package integrates with Laravel's encryption system and either the built-in `encrypt()` and `decrypt()` helpers or the `Crypt` facade may be used when you want to utilize your default driver.

In order to use additional drivers, the `Crypt` facade must be used:

```php
use Illuminate\Support\Facades\Crypt;

$encrypted = Crypt::driver('something')->encrypt('Hello world.');
```

### Key Generation
Encryption keys can be generated using the command `php artisan crypt:key:generate` and there are the following options available:

- `--driver` the name of the driver from your configuration to use.
- `--schema` an override of the schema to use when generating a key.
- `--cipher` an override of the cipher to use when generating a key.
- `--environment` what environment variable to set in your .env file. Defaults to `APP_KEY`.
- `--show` to display the key instead of applying it to configuration and environment.
- `--force` force the operation to run when in production.

## Extensions
Custom schemas can be added by simply extending `EncryptionManager` and registering a key generator in your service provider's `register` function:

```php
public function register()
{
    EncryptionManager::registerKeyGenerator('schema_name', function () {
        return SpecialSchema::class;
    });

    $this->app->resolving('encrypter', function ($encrypter) {
        $encrypter->extend('schema_name', function ($config) {
            return new SpecialSchema($config);
        });
    });
}
```

Custom schemas are expected to implement the `Wizofgoz\Cryptographer\Contracts\Schema` contract.
