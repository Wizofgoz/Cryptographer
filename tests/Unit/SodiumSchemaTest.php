<?php

namespace Wizofgoz\Cryptographer\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Wizofgoz\Cryptographer\Schema\SodiumSchema;

class SodiumSchemaTest extends TestCase
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
        $f = new SodiumSchema(SodiumSchema::generateKey());

        $plaintext = 'bar';
        $ciphertext = $f->encrypt($plaintext);

        $this->assertEquals($plaintext, $f->decrypt($ciphertext));
    }

    public function testGenerateKeyWithChachaCipher()
    {
        $f = new SodiumSchema(SodiumSchema::generateKey(SodiumSchema::CIPHER_CHACHA), SodiumSchema::CIPHER_CHACHA);

        $plaintext = 'bar';
        $ciphertext = $f->encrypt($plaintext);

        $this->assertEquals($plaintext, $f->decrypt($ciphertext));
    }

    public function testGenerateKeyWithAesCipher()
    {
        if (!sodium_crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('AES-256-GCM is not supported for this architecture');
        }

        $f = new SodiumSchema(SodiumSchema::generateKey(SodiumSchema::CIPHER_AES_256), SodiumSchema::CIPHER_AES_256);

        $plaintext = 'bar';
        $ciphertext = $f->encrypt($plaintext);

        $this->assertEquals($plaintext, $f->decrypt($ciphertext));
    }

    public function testGenerateKeyWithXChachaIETFCipher()
    {
        $f = new SodiumSchema(SodiumSchema::generateKey(SodiumSchema::CIPHER_X_CHACHA_IETF), SodiumSchema::CIPHER_X_CHACHA_IETF);

        $plaintext = 'bar';
        $ciphertext = $f->encrypt($plaintext);

        $this->assertEquals($plaintext, $f->decrypt($ciphertext));
    }

    public function testEncryption()
    {
        $e = new SodiumSchema(SodiumSchema::generateKey());
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testRawStringEncryption()
    {
        $e = new SodiumSchema(SodiumSchema::generateKey());
        $encrypted = $e->encryptString('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decryptString($encrypted));
    }

    public function testWithChachaCipher()
    {
        $e = new SodiumSchema(SodiumSchema::generateKey(SodiumSchema::CIPHER_CHACHA), SodiumSchema::CIPHER_CHACHA);
        $encrypted = $e->encrypt('bar');

        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));

        $e = new SodiumSchema(SodiumSchema::generateKey(SodiumSchema::CIPHER_CHACHA), SodiumSchema::CIPHER_CHACHA);
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testWithAesCipher()
    {
        if (!sodium_crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('AES-256-GCM is not supported for this architecture');
        }

        $e = new SodiumSchema(SodiumSchema::generateKey(SodiumSchema::CIPHER_AES_256), SodiumSchema::CIPHER_AES_256);
        $encrypted = $e->encrypt('bar');

        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));

        $e = new SodiumSchema(SodiumSchema::generateKey(SodiumSchema::CIPHER_AES_256), SodiumSchema::CIPHER_AES_256);
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testWithXChachaIETFCipher()
    {
        $e = new SodiumSchema(SodiumSchema::generateKey(SodiumSchema::CIPHER_X_CHACHA_IETF), SodiumSchema::CIPHER_X_CHACHA_IETF);
        $encrypted = $e->encrypt('bar');

        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));

        $e = new SodiumSchema(SodiumSchema::generateKey(SodiumSchema::CIPHER_X_CHACHA_IETF), SodiumSchema::CIPHER_X_CHACHA_IETF);
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
        $e = new SodiumSchema(SodiumSchema::generateKey());

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
        $a = new SodiumSchema(SodiumSchema::generateKey());
        $b = new SodiumSchema(SodiumSchema::generateKey());

        $b->decrypt($a->encrypt('baz'));
    }
}
