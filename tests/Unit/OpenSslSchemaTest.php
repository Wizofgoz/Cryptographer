<?php

namespace Wizofgoz\Cryptographer\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Wizofgoz\Cryptographer\Schema\OpenSslSchema;

class OpenSslSchemaTest extends TestCase
{
    public function testEncryption()
    {
        $e = new OpenSslSchema(str_repeat('a', 16));
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testRawStringEncryption()
    {
        $e = new OpenSslSchema(str_repeat('a', 16));
        $encrypted = $e->encryptString('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decryptString($encrypted));
    }

    public function testWithCustomCipher()
    {
        $e = new OpenSslSchema(str_repeat('b', 32), OpenSslSchema::CIPHER_AES_256);
        $encrypted = $e->encrypt('bar');

        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));

        $e = new OpenSslSchema(random_bytes(32), OpenSslSchema::CIPHER_AES_256);
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testGenerateKey()
    {
        $f = new OpenSslSchema(OpenSslSchema::generateKey());

        $plaintext = 'bar';
        $ciphertext = $f->encrypt($plaintext);

        $this->assertEquals($plaintext, $f->decrypt($ciphertext));
    }

    public function testGenerateKeyWithCustomCipher()
    {
        $f = new OpenSslSchema(OpenSslSchema::generateKey(OpenSslSchema::CIPHER_AES_256), OpenSslSchema::CIPHER_AES_256);

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
        $e = new OpenSslSchema(str_repeat('a', 16));

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
        $a = new OpenSslSchema(str_repeat('a', 16));
        $b = new OpenSslSchema(str_repeat('b', 16));

        $b->decrypt($a->encrypt('baz'));
    }

    /**
     * @expectedException \Illuminate\Contracts\Encryption\DecryptException
     * @expectedExceptionMessage The payload is invalid.
     */
    public function testExceptionThrownWhenIvIsTooLong()
    {
        $e = new OpenSslSchema(str_repeat('a', 16));

        $payload = $e->encrypt('foo');

        $data = json_decode(base64_decode($payload), true);
        $data['iv'] .= $data['value'][0];
        $data['value'] = substr($data['value'], 1);
        $modified_payload = base64_encode(json_encode($data));

        $e->decrypt($modified_payload);
    }
}
