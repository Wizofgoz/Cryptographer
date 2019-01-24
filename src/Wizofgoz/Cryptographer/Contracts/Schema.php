<?php

namespace Wizofgoz\Cryptographer\Contracts;

interface Schema
{
    /**
     * Encrypt the given value.
     *
     * @param  mixed  $value
     * @param  bool  $serialize
     * @return mixed
     */
    public function encrypt($value, $serialize = true);

    /**
     * Encrypt a string without serialization.
     *
     * @param  string  $value
     * @return string
     *
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     */
    public function encryptString($value);

    /**
     * Decrypt the given value.
     *
     * @param  mixed  $payload
     * @param  bool  $unserialize
     * @return mixed
     */
    public function decrypt($payload, $unserialize = true);

    /**
     * Decrypt the given string without unserialization.
     *
     * @param  string  $payload
     * @return string
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    public function decryptString($payload);

    /**
     * Return the key set on the encrypter.
     *
     * @return string
     */
    public function getKey();

    /**
     * Generate a new key for the chosen cipher.
     *
     * @param  string  $cipher
     * @return mixed
     */
    public static function generateKey($cipher);
}