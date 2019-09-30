<?php

namespace Wizofgoz\Cryptographer\Tests\Unit;

use Illuminate\Support\Str;
use PHPUnit\Framework\TestCase;
use Wizofgoz\Cryptographer\KeyDrivers\AwsKeyDriver;

class AwsKeyDriverTest extends TestCase
{
    const KEY_LENGTH = 16;

    public $options = [
        'region'     => 'us-west-2',
        'profile'    => 'default',
        'master-key' => '',
        'context'    => [],
    ];

    protected function setUp(): void
    {
        if (($key = getenv('AWS_MASTER_KEY')) === false) {
            $this->markTestSkipped();
        }

        $this->options['master-key'] = getenv('AWS_MASTER_KEY');
    }

    public function testGenerateKey()
    {
        $encryptedKey = AwsKeyDriver::generateKey(self::KEY_LENGTH, $this->options);
        $k = new AwsKeyDriver($encryptedKey, $this->options);

        $this->assertEquals(
            self::KEY_LENGTH,
            strlen($k->getKey())
        );
    }

    public function testGenerateKeyWithAlternateKeyDefinition()
    {
        if (!Str::startsWith($this->options['master-key'], 'arn')) {
            $this->markTestSkipped("key not in ARN format so skipping");
        }

        $options = $this->options;

        // get last element of key split by ":" and trim "key/" from the front
        $arr = explode(':', $options['master-key']);
        $key = Str::after(end($arr), 'key/');

        $options['master-key'] = $key;
        $encryptedKey = AwsKeyDriver::generateKey(self::KEY_LENGTH, $options);
        $k = new AwsKeyDriver($encryptedKey, $options);

        $this->assertEquals(
            self::KEY_LENGTH,
            strlen($k->getKey())
        );
    }

    public function testExceptionIfMissingOption()
    {
        $this->expectException(\RuntimeException::class);
        $driver = new AwsKeyDriver('', []);
    }

    public function testIsRotatable()
    {
        $driver = new AwsKeyDriver('', $this->options);

        $this->assertTrue($driver->isKeyRotatable());
    }

    public function testReEncrypt()
    {
        $key = AwsKeyDriver::generateKey(self::KEY_LENGTH, $this->options);
        $driver = new AwsKeyDriver($key, $this->options);
        $newDriver = new AwsKeyDriver($driver->reEncrypt(), $this->options);

        $this->assertEquals($driver->getKey(), $newDriver->getKey());
    }
}
