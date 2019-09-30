<?php

namespace Wizofgoz\Cryptographer\Tests\Integration;

use Orchestra\Testbench\TestCase;
use InvalidArgumentException;
use RuntimeException;
use Wizofgoz\Cryptographer\Crypt;
use Wizofgoz\Cryptographer\EncryptionManager;
use Wizofgoz\Cryptographer\EncryptionServiceProvider;
use Wizofgoz\Cryptographer\Engines\OpenSslEngine;

class EncryptionTest extends TestCase
{
    protected function getEnvironmentSetUp($app)
    {
        $app['config']->set('cryptographer', [
            'default' => 'default',
            'drivers' => [
                'default' => [
                    'engine' => 'openssl',
                    'cipher' => OpenSslEngine::CIPHER_AES_256,
                    'key'    => 'default',
                ],
            ],
            'keys' => [
                'default' => [
                    'driver' => 'local',
                    'value' => 'base64:IUHRqAQ99pZ0A1MPjbuv1D6ff3jxv0GIvS2qIW4JNU4=',
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
            $this->app['config']->get('cryptographer.drivers.default.engine'),
            $this->app['config']->get('cryptographer.keys.default.driver'),
            $this->app['config']->get('cryptographer.drivers.default.cipher')
        );

        $this->app['config']->set('cryptographer.keys.default.value', $key);

        $e = $this->app->make('encrypter');

        $plaintext = 'bar';
        $ciphertext = $e->encrypt($plaintext);

        $this->assertEquals($plaintext, $e->decrypt($ciphertext));
    }

    public function test_encryption_will_not_be_usable_when_missing_app_key()
    {
        $this->expectException(RuntimeException::class);

        $this->app['config']->set('cryptographer.keys.default.value', null);

        $e = $this->app->make('encrypter');

        $e->encrypt('bar');
    }

    public function test_do_not_allow_longer_key()
    {
        $this->expectException(RuntimeException::class);

        $this->app['config']->set('cryptographer.keys.default.value', str_repeat('z', 32));
        $this->app['config']->set('cryptographer.drivers.default.cipher', OpenSslEngine::CIPHER_AES_128);

        $e = $this->app->make('encrypter');

        $e->encrypt('bar');
    }

    public function test_with_bad_key_length()
    {
        $this->expectException(RuntimeException::class);

        $this->app['config']->set('cryptographer.keys.default.value', str_repeat('z', 5));

        $e = $this->app->make('encrypter');

        $e->encrypt('bar');
    }

    public function test_with_bad_key_length_alternative_cipher()
    {
        $this->expectException(RuntimeException::class);

        $this->app['config']->set('cryptographer.keys.default.value', str_repeat('z', 16));

        $e = $this->app->make('encrypter');

        $e->encrypt('bar');
    }

    public function testWithUnsupportedCipher()
    {
        $this->expectException(InvalidArgumentException::class);

        $this->app['config']->set('cryptographer.keys.default.value', str_repeat('z', 16));
        $this->app['config']->set('cryptographer.drivers.default.cipher', 'AES-256-CFB8');

        $e = $this->app->make('encrypter');

        $e->encrypt('bar');
    }

    public function testFacade()
    {
        $plaintext = 'asdfghjkl';
        $ciphertext = Crypt::encrypt($plaintext);

        $this->assertNotEquals($plaintext, $ciphertext);
        $this->assertEquals($plaintext, Crypt::decrypt($ciphertext));
    }
}
