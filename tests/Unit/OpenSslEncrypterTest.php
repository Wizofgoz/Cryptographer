<?php

namespace Wizofgoz\Cryptographer\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Wizofgoz\Cryptographer\OpenSslEncrypter;

class OpenSslEncrypterTest extends TestCase
{
    public function testEncryption()
    {
        $e = new OpenSslEncrypter(str_repeat('a', 16));
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testRawStringEncryption()
    {
        $e = new OpenSslEncrypter(str_repeat('a', 16));
        $encrypted = $e->encryptString('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decryptString($encrypted));
    }

    public function testEncryptionUsingBase64EncodedKey()
    {
        $e = new OpenSslEncrypter(random_bytes(16));
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testWithCustomCipher()
    {
        $e = new OpenSslEncrypter(str_repeat('b', 32), OpenSslEncrypter::AES_256);
        $encrypted = $e->encrypt('bar');

        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));

        $e = new OpenSslEncrypter(random_bytes(32), OpenSslEncrypter::AES_256);
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testGenerateKey()
    {
        $f = new OpenSslEncrypter(OpenSslEncrypter::generateKey());

        $plaintext = 'bar';
        $ciphertext = $f->encrypt($plaintext);

        $this->assertEquals($plaintext, $f->decrypt($ciphertext));
    }

    public function testGenerateKeyWithCustomCipher()
    {
        $f = new OpenSslEncrypter(OpenSslEncrypter::generateKey(OpenSslEncrypter::AES_256), OpenSslEncrypter::AES_256);

        $plaintext = 'bar';
        $ciphertext = $f->encrypt($plaintext);

        $this->assertEquals($plaintext, $f->decrypt($ciphertext));
    }

    /**
     * @expectedException \Illuminate\Contracts\Encryption\DecryptException
     * @expectedExceptionMessage The payload is invalid.
     */
    public function testExceptionThrownWhenPayloadIsInvalid()
    {
        $e = new OpenSslEncrypter(str_repeat('a', 16));

        $payload = $e->encrypt('foo');

        $payload = str_shuffle($payload);

        $e->decrypt($payload);
    }

    /**
     * @expectedException \Illuminate\Contracts\Encryption\DecryptException
     * @expectedExceptionMessage The MAC is invalid.
     */
    public function testExceptionThrownWithDifferentKey()
    {
        $a = new OpenSslEncrypter(str_repeat('a', 16));
        $b = new OpenSslEncrypter(str_repeat('b', 16));

        $b->decrypt($a->encrypt('baz'));
    }

    /**
     * @expectedException \Illuminate\Contracts\Encryption\DecryptException
     * @expectedExceptionMessage The payload is invalid.
     */
    public function testExceptionThrownWhenIvIsTooLong()
    {
        $e = new OpenSslEncrypter(str_repeat('a', 16));

        $payload = $e->encrypt('foo');

        $data = json_decode(base64_decode($payload), true);
        $data['iv'] .= $data['value'][0];
        $data['value'] = substr($data['value'], 1);
        $modified_payload = base64_encode(json_encode($data));

        $e->decrypt($modified_payload);
    }
}
