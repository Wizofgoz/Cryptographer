<?php

namespace Wizofgoz\Cryptographer\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Wizofgoz\Cryptographer\Engines\SodiumEngine;

class SodiumEngineTest extends TestCase
{
    protected function setUp()
    {
        parent::setUp();

        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension should be available to run tests');
        }
    }

    public function testGenerateKey()
    {
        $f = new SodiumEngine(SodiumEngine::generateKey());

        $plaintext = 'bar';
        $ciphertext = $f->encrypt($plaintext);

        $this->assertEquals($plaintext, $f->decrypt($ciphertext));
    }

    public function testGenerateKeyWithChachaCipher()
    {
        $f = new SodiumEngine(SodiumEngine::generateKey(SodiumEngine::CIPHER_CHACHA), SodiumEngine::CIPHER_CHACHA);

        $plaintext = 'bar';
        $ciphertext = $f->encrypt($plaintext);

        $this->assertEquals($plaintext, $f->decrypt($ciphertext));
    }

    public function testGenerateKeyWithAesCipher()
    {
        if (!sodium_crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('AES-256-GCM is not supported for this architecture');
        }

        $f = new SodiumEngine(SodiumEngine::generateKey(SodiumEngine::CIPHER_AES_256), SodiumEngine::CIPHER_AES_256);

        $plaintext = 'bar';
        $ciphertext = $f->encrypt($plaintext);

        $this->assertEquals($plaintext, $f->decrypt($ciphertext));
    }

    public function testGenerateKeyWithXChachaIETFCipher()
    {
        $f = new SodiumEngine(SodiumEngine::generateKey(SodiumEngine::CIPHER_X_CHACHA_IETF), SodiumEngine::CIPHER_X_CHACHA_IETF);

        $plaintext = 'bar';
        $ciphertext = $f->encrypt($plaintext);

        $this->assertEquals($plaintext, $f->decrypt($ciphertext));
    }

    public function testEncryption()
    {
        $e = new SodiumEngine(SodiumEngine::generateKey());
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testRawStringEncryption()
    {
        $e = new SodiumEngine(SodiumEngine::generateKey());
        $encrypted = $e->encryptString('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decryptString($encrypted));
    }

    public function testWithChachaCipher()
    {
        $e = new SodiumEngine(SodiumEngine::generateKey(SodiumEngine::CIPHER_CHACHA), SodiumEngine::CIPHER_CHACHA);
        $encrypted = $e->encrypt('bar');

        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));

        $e = new SodiumEngine(SodiumEngine::generateKey(SodiumEngine::CIPHER_CHACHA), SodiumEngine::CIPHER_CHACHA);
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testWithAesCipher()
    {
        if (!sodium_crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('AES-256-GCM is not supported for this architecture');
        }

        $e = new SodiumEngine(SodiumEngine::generateKey(SodiumEngine::CIPHER_AES_256), SodiumEngine::CIPHER_AES_256);
        $encrypted = $e->encrypt('bar');

        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));

        $e = new SodiumEngine(SodiumEngine::generateKey(SodiumEngine::CIPHER_AES_256), SodiumEngine::CIPHER_AES_256);
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testWithXChachaIETFCipher()
    {
        $e = new SodiumEngine(SodiumEngine::generateKey(SodiumEngine::CIPHER_X_CHACHA_IETF), SodiumEngine::CIPHER_X_CHACHA_IETF);
        $encrypted = $e->encrypt('bar');

        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));

        $e = new SodiumEngine(SodiumEngine::generateKey(SodiumEngine::CIPHER_X_CHACHA_IETF), SodiumEngine::CIPHER_X_CHACHA_IETF);
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
        $e = new SodiumEngine(SodiumEngine::generateKey());

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
        $a = new SodiumEngine(SodiumEngine::generateKey());
        $b = new SodiumEngine(SodiumEngine::generateKey());

        $b->decrypt($a->encrypt('baz'));
    }
}
