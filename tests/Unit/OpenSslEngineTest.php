<?php

namespace Wizofgoz\Cryptographer\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Wizofgoz\Cryptographer\Engines\OpenSslEngine;
use Wizofgoz\Cryptographer\KeyDrivers\LocalKeyDriver;

class OpenSslEngineTest extends TestCase
{
    public function testEncryption()
    {
        $k = new LocalKeyDriver(str_repeat('a', 16), []);
        $e = new OpenSslEngine($k);
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testRawStringEncryption()
    {
        $k = new LocalKeyDriver(str_repeat('a', 16), []);
        $e = new OpenSslEngine($k);
        $encrypted = $e->encryptString('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decryptString($encrypted));
    }

    public function testWithCustomCipher()
    {
        $k = new LocalKeyDriver(str_repeat('b', 32), []);
        $e = new OpenSslEngine($k, OpenSslEngine::CIPHER_AES_256);
        $encrypted = $e->encrypt('bar');

        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));

        $k2 = new LocalKeyDriver(random_bytes(32), []);
        $e = new OpenSslEngine($k2, OpenSslEngine::CIPHER_AES_256);
        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    /**
     * @expectedException \Illuminate\Contracts\Encryption\DecryptException
     * @expectedExceptionMessage The payload is invalid.
     */
    public function testExceptionThrownWhenPayloadIsInvalid()
    {
        $k = new LocalKeyDriver(str_repeat('a', 16), []);
        $e = new OpenSslEngine($k);

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
        $k = new LocalKeyDriver(str_repeat('a', 16), []);
        $a = new OpenSslEngine($k);
        $k2 = new LocalKeyDriver(str_repeat('b', 16), []);
        $b = new OpenSslEngine($k2);

        $b->decrypt($a->encrypt('baz'));
    }

    /**
     * @expectedException \Illuminate\Contracts\Encryption\DecryptException
     * @expectedExceptionMessage The payload is invalid.
     */
    public function testExceptionThrownWhenIvIsTooLong()
    {
        $k = new LocalKeyDriver(str_repeat('a', 16), []);
        $e = new OpenSslEngine($k);

        $payload = $e->encrypt('foo');

        $data = json_decode(base64_decode($payload), true);
        $data['iv'] .= $data['value'][0];
        $data['value'] = substr($data['value'], 1);
        $modified_payload = base64_encode(json_encode($data));

        $e->decrypt($modified_payload);
    }
}
