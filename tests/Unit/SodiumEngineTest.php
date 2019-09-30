<?php

namespace Wizofgoz\Cryptographer\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Wizofgoz\Cryptographer\Engines\SodiumEngine;
use Wizofgoz\Cryptographer\KeyDrivers\LocalKeyDriver;

class SodiumEngineTest extends TestCase
{
    protected function setUp()
    {
        parent::setUp();

        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension should be available to run tests');
        }
    }

    public function testEncryption()
    {
        $k = new LocalKeyDriver(str_repeat('a', SodiumEngine::getKeyLength()), []);
        $e = new SodiumEngine($k);
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testRawStringEncryption()
    {
        $k = new LocalKeyDriver(str_repeat('a', SodiumEngine::getKeyLength()), []);
        $e = new SodiumEngine($k);
        $encrypted = $e->encryptString('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decryptString($encrypted));
    }

    public function testWithChachaCipher()
    {
        $k = new LocalKeyDriver(str_repeat('a', SodiumEngine::getKeyLength(SodiumEngine::CIPHER_CHACHA)), []);
        $e = new SodiumEngine($k, SodiumEngine::CIPHER_CHACHA);
        $encrypted = $e->encrypt('bar');

        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));

        $k2 = new LocalKeyDriver(str_repeat('b', SodiumEngine::getKeyLength(SodiumEngine::CIPHER_CHACHA)), []);
        $e = new SodiumEngine($k2, SodiumEngine::CIPHER_CHACHA);
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testWithAesCipher()
    {
        if (!sodium_crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('AES-256-GCM is not supported for this architecture');
        }

        $k = new LocalKeyDriver(str_repeat('a', SodiumEngine::getKeyLength(SodiumEngine::CIPHER_AES_256)), []);
        $e = new SodiumEngine($k, SodiumEngine::CIPHER_AES_256);
        $encrypted = $e->encrypt('bar');

        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));

        $k2 = new LocalKeyDriver(str_repeat('a', SodiumEngine::getKeyLength(SodiumEngine::CIPHER_AES_256)), []);
        $e = new SodiumEngine($k2, SodiumEngine::CIPHER_AES_256);
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testWithXChachaIETFCipher()
    {
        $k = new LocalKeyDriver(str_repeat('a', SodiumEngine::getKeyLength(SodiumEngine::CIPHER_X_CHACHA_IETF)), []);
        $e = new SodiumEngine($k, SodiumEngine::CIPHER_X_CHACHA_IETF);
        $encrypted = $e->encrypt('bar');

        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));

        $k2 = new LocalKeyDriver(str_repeat('a', SodiumEngine::getKeyLength(SodiumEngine::CIPHER_X_CHACHA_IETF)), []);
        $e = new SodiumEngine($k2, SodiumEngine::CIPHER_X_CHACHA_IETF);
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    /**
     * @expectedException \Illuminate\Contracts\Encryption\DecryptException
     * @expectedExceptionMessage Could not decrypt the data.
     */
    public function testExceptionThrownWhenPayloadIsInvalid()
    {
        $k = new LocalKeyDriver(str_repeat('a', SodiumEngine::getKeyLength()), []);
        $e = new SodiumEngine($k);

        $payload = $e->encrypt('foo');

        $payload = str_shuffle($payload);

        $e->decrypt($payload);
    }

    /**
     * @expectedException \Illuminate\Contracts\Encryption\DecryptException
     * @expectedExceptionMessage Could not decrypt the data.
     */
    public function testExceptionThrownWithDifferentKey()
    {
        $k = new LocalKeyDriver(str_repeat('a', SodiumEngine::getKeyLength()), []);
        $a = new SodiumEngine($k);
        $k2 = new LocalKeyDriver(str_repeat('b', SodiumEngine::getKeyLength()), []);
        $b = new SodiumEngine($k2);

        $b->decrypt($a->encrypt('baz'));
    }
}
