<?php

namespace Wizofgoz\Cryptographer\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Wizofgoz\Cryptographer\KeyDrivers\LocalKeyDriver;

class LocalKeyDriverTest extends TestCase
{
    const KEY_LENGTH = 16;

    public function testGenerateKey()
    {
        $key = LocalKeyDriver::generateKey(self::KEY_LENGTH);
        $k = new LocalKeyDriver($key, []);

        $this->assertEquals(self::KEY_LENGTH, strlen($k->getKey()));
    }

    public function testIsRotatable()
    {
        $driver = new LocalKeyDriver('', []);

        $this->assertFalse($driver->isKeyRotatable());
    }

    public function testReEncrypt()
    {
        $key = 'asdfghjkl';
        $driver = new LocalKeyDriver($key, []);

        $this->assertEquals($key, $driver->reEncrypt());
    }
}
