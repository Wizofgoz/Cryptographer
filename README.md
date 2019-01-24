# Cryptographer

## Introduction
Cryptographer provides an extensible replacement for Laravel's encryption service. It also allows you to define multiple drivers that can be used for different areas of your application.

## Installation
You may use Composer to install Cryptographer into your Laravel project:

`composer require wizofgoz/cryptographer`

After installing, publish the configuration:

`php artisan vendor:publish --provider=Wizofgoz\Cryptographer\EncryptionServiceProvider`

## Configuration
After publishing the configuration file, it will be located at `config/cryptographer.php` This file allows you to define the encryption drivers.

### Default Driver
This option allows you to define the default driver to use when using the encryption service. If no default driver is set, the first entry in the drivers array will be used.

`'default' => 'default'`

### Available Drivers
This option allows for defining the encryption drivers available to your application. Each entry in the list MUST contain a schema, cipher, and key for proper use.

```php
'drivers' => [
    'default' => [
        'schema' => 'openssl',
        'cipher' => OpenSslEncrypter::AES_128,
        'key'    => env('APP_KEY'),
    ],
],
```

## Usage
This package effectively replaces Laravel's encryption system so the built-in `encrypt()` helper or the `Crypt` facade may be used when you want to utilize your default driver.

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
- `--env` what environment variable to set in your .env file. Defaults to `APP_KEY`.
- `--show` to display the key instead of applying it to configuration and environment.
- `--force` force the operation to run when in production.

## Extensions
Custom schemas can be added by simply extending `EncryptionManager` and registering a key generator in your service provider's `register` function:

```php
public function register()
{
    EncryptionManager::registerKeyGenerator('special', function () {
        return SpecialEncrypter::class;
    });

    $this->app->resolving('encrypter', function ($encrypter) {
        $encrypter->extend('special', function ($config) {
            return new SpecialEncrypter($config);
        });
    });
}
```

Custom schemas are expected to implement the `Wizofgoz\Cryptographer\Contracts\Schema` contract.