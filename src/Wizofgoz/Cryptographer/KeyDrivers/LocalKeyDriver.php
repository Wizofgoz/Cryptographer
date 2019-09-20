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
     * @param $length
     * @return string
     * @throws \Exception
     */
    public static function generateKey($length)
    {
        return random_bytes($length);
    }

    public function getKey()
    {
        return $this->key;
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
