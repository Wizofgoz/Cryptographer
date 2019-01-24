<?php

namespace Wizofgoz\Cryptographer\Tests\Integration;

use Orchestra\Testbench\TestCase;
use RuntimeException;
use Wizofgoz\Cryptographer\EncryptionManager;
use Wizofgoz\Cryptographer\EncryptionServiceProvider;
use Wizofgoz\Cryptographer\OpenSslEncrypter;

class EncryptionTest extends TestCase
{
    protected function getEnvironmentSetUp($app)
    {
        $app['config']->set('cryptographer', [
            'default' => 'default',
            'drivers' => [
                'default' => [
                    'schema' => 'openssl',
                    'cipher' => OpenSslEncrypter::AES_256,
                    'key'    => 'base64:IUHRqAQ99pZ0A1MPjbuv1D6ff3jxv0GIvS2qIW4JNU4=',
                ],
            ],
        ]);
    }

    protected function getPackageProviders($app)
    {
        return [EncryptionServiceProvider::class];
    }

    public function test_encryption_provider_bind()
    {
        self::assertInstanceOf(EncryptionManager::class, $this->app->make('encrypter'));
    }

    public function test_generate_key()
    {
        $key = EncryptionManager::generateKey(
            $this->app['config']->get('cryptographer.drivers.default.schema'),
            $this->app['config']->get('cryptographer.drivers.default.cipher')
        );

        $this->app['config']->set('cryptographer.drivers.default.key', $key);

        $e = $this->app->make('encrypter');

        $plaintext = 'bar';
        $ciphertext = $e->encrypt($plaintext);

        $this->assertEquals($plaintext, $e->decrypt($ciphertext));
    }

    public function test_encryption_will_not_be_usable_when_missing_app_key()
    {
        $this->expectException(RuntimeException::class);

        $this->app['config']->set('cryptographer.drivers.default.key', null);

        $e = $this->app->make('encrypter');

        $e->encrypt('bar');
    }

    public function test_do_not_allow_longer_key()
    {
        $this->expectException(RuntimeException::class);

        $this->app['config']->set('cryptographer.drivers.default.key', str_repeat('z', 32));
        $this->app['config']->set('cryptographer.drivers.default.cipher', OpenSslEncrypter::AES_128);

        $e = $this->app->make('encrypter');

        $e->encrypt('bar');
    }

    public function test_with_bad_key_length()
    {
        $this->expectException(RuntimeException::class);

        $this->app['config']->set('cryptographer.drivers.default.key', str_repeat('z', 5));

        $e = $this->app->make('encrypter');

        $e->encrypt('bar');
    }

    public function test_with_bad_key_length_alternative_cipher()
    {
        $this->expectException(RuntimeException::class);

        $this->app['config']->set('cryptographer.drivers.default.key', str_repeat('z', 16));

        $e = $this->app->make('encrypter');

        $e->encrypt('bar');
    }

    public function testWithUnsupportedCipher()
    {
        $this->expectException(RuntimeException::class);

        $this->app['config']->set('cryptographer.drivers.default.key', str_repeat('z', 16));
        $this->app['config']->set('cryptographer.drivers.default.cipher', 'AES-256-CFB8');

        $e = $this->app->make('encrypter');

        $e->encrypt('bar');
    }
}
