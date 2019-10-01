<?php

namespace Wizofgoz\Cryptographer;

use Illuminate\Support\Facades\Facade;
use Wizofgoz\Cryptographer\Contracts\Engine;

/**
 * @method static string generateKey(string $engine, string $keyDriver, string $cipher = null, array $additionalOptions = [])
 * @method static string encrypt(mixed $value, bool $serialize = true)
 * @method static string encryptString(string $value)
 * @method static mixed decrypt(string $payload, bool $unserialize = true)
 * @method static string decryptString(string $payload)
 * @method static Engine driver(string $driver = null)
 * @method static string getKey()
 *
 * @see \Wizofgoz\Cryptographer\EncryptionManager
 */
class Crypt extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'encrypter';
    }
}
