<?php

namespace Wizofgoz\Cryptographer\Schema;

use RuntimeException;
use Wizofgoz\Cryptographer\Contracts\Schema as SchemaContract;

abstract class Schema implements SchemaContract
{
    const KEY_LENGTHS = [];

    const DEFAULT_CIPHER = null;

    /**
     * The encryption key.
     *
     * @var string
     */
    protected $key;

    /**
     * The algorithm used for encryption.
     *
     * @var string
     */
    protected $cipher;

    /**
     * Create a new schema instance.
     *
     * @param string $key
     * @param string $cipher
     *
     * @return void
     */
    public function __construct($key, $cipher = null)
    {
        $cipher = static::resolveCipher($cipher);
        $key = (string) $key;

        if (static::supported($key, $cipher)) {
            $this->key = $key;
            $this->cipher = $cipher;
        } else {
            $supported = implode(', ', array_keys(static::KEY_LENGTHS));

            throw new RuntimeException("The only supported ciphers are {$supported} with the correct key lengths.");
        }
    }

    /**
     * Determine the cipher that should be considered.
     *
     * @param string|null $cipher
     * @return string
     */
    protected static function resolveCipher($cipher = null)
    {
        if ($cipher === null) {
            $cipher = static::DEFAULT_CIPHER;
        }

        return $cipher;
    }

    /**
     * Determine if the given key and cipher combination is valid.
     *
     * @param  string  $key
     * @param  string  $cipher
     * @return bool
     */
    protected static function supported($key, $cipher)
    {
        $length = mb_strlen($key, '8bit');

        return isset(static::KEY_LENGTHS[$cipher]) && $length === static::KEY_LENGTHS[$cipher];
    }

    /**
     * Create a new encryption key for the given cipher.
     *
     * @param string|null $cipher
     *
     * @throws \Exception
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    public static function generateKey($cipher = null)
    {
        $cipher = static::resolveCipher($cipher);

        if (!isset(static::KEY_LENGTHS[$cipher])) {
            throw new \InvalidArgumentException("{$cipher} is not a supported cipher.");
        }

        return random_bytes(static::KEY_LENGTHS[$cipher]);
    }

    /**
     * Get the appropriate nonce length for the current cipher.
     *
     * @return int
     */
    abstract protected function getNonceLength();

    /**
     * Generate an appropriate nonce for the current cipher.
     *
     * @return string
     *
     * @throws \Exception
     */
    protected function generateNonce()
    {
        return random_bytes($this->getNonceLength());
    }

    /**
     * Get the encryption key.
     *
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }
}
