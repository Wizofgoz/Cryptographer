<?php

namespace Wizofgoz\Cryptographer\KeyDrivers;

use Wizofgoz\Cryptographer\Contracts\KeyDriver;

class LocalKeyDriver implements KeyDriver
{
    private $key;

    public function __construct($key, array $options)
    {
        $this->key = $key;
    }

    /**
     * @param int   $length
     * @param array $additionalOptions
     *
     * @throws \Exception
     *
     * @return string
     */
    public static function generateKey($length, array $additionalOptions = [])
    {
        return random_bytes($length);
    }

    public function getKey()
    {
        return $this->key;
    }

    public function isKeyRotatable(): bool
    {
        return false;
    }

    /**
     * Re-encrypt the key and return it.
     *
     * @return string
     */
    public function reEncrypt(): string
    {
        // just return the key since it's not encrypted
        return $this->getKey();
    }

    /**
     * Clears plaintext version of key from memory.
     * Not applicable here because key is always plaintext.
     *
     * @return void
     */
    public function clearMemory()
    {
    }
}
