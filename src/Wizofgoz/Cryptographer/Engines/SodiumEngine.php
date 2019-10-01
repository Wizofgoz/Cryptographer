<?php

namespace Wizofgoz\Cryptographer\Engines;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;

class SodiumEngine extends Engine
{
    const ENGINE_NAME = 'sodium';

    const CIPHER_AES_256 = 'AES-256-GCM';
    const CIPHER_CHACHA = 'CHACHA-20-POLY-1305';
    const CIPHER_CHACHA_IETF = 'CHACHA-20-POLY-1305-IETF';
    const CIPHER_X_CHACHA_IETF = 'XCHACHA-20-POLY-1305-IETF';

    const DEFAULT_CIPHER = self::CIPHER_X_CHACHA_IETF;

    const KEY_LENGTHS = [
        self::CIPHER_AES_256       => SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES,
        self::CIPHER_CHACHA        => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES,
        self::CIPHER_CHACHA_IETF   => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES,
        self::CIPHER_X_CHACHA_IETF => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES,
    ];

    /**
     * Determine if the given key and cipher combination is valid.
     *
     * @param string $key
     * @param string $cipher
     *
     * @return bool
     */
    public static function supported($key, $cipher)
    {
        if ($cipher === static::CIPHER_AES_256 && !sodium_crypto_aead_aes256gcm_is_available()) {
            return false;
        }

        return parent::supported($key, $cipher);
    }

    /**
     * Encrypt the given value.
     *
     * @param mixed $value
     * @param bool  $serialize
     *
     * @throws \Exception
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     *
     * @return string
     */
    public function encrypt($value, $serialize = true)
    {
        $value = $serialize ? serialize($value) : $value;

        $value = $this->doEncrypt($value);

        if ($value === false) {
            throw new EncryptException('Could not encrypt the data');
        }

        return sodium_bin2hex($value);
    }

    /**
     * Encrypt a string without serialization.
     *
     * @param string $value
     *
     * @throws \Exception
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     *
     * @return string
     */
    public function encryptString($value)
    {
        return $this->encrypt($value, false);
    }

    /**
     * Get the appropriate nonce length for the current cipher.
     *
     * @return int
     */
    protected function getNonceLength()
    {
        switch ($this->cipher) {
            case static::CIPHER_AES_256:
                return SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES;

            case static::CIPHER_CHACHA:
                return SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES;

            case static::CIPHER_CHACHA_IETF:
                return SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES;

            // documented here:
            // https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
            case static::CIPHER_X_CHACHA_IETF:
                return 24;

            default:
                return 0;
        }
    }

    /**
     * Run encryption on the given value.
     *
     * @param $value
     *
     * @throws \Exception
     *
     * @return bool|string
     */
    protected function doEncrypt($value)
    {
        $nonce = $this->generateNonce();

        switch ($this->cipher) {
            case static::CIPHER_AES_256:
                return $nonce.sodium_crypto_aead_aes256gcm_encrypt($value, $nonce, $nonce, $this->getKey());

            case static::CIPHER_CHACHA:
                return $nonce.sodium_crypto_aead_chacha20poly1305_encrypt($value, $nonce, $nonce, $this->getKey());

            case static::CIPHER_CHACHA_IETF:
                return $nonce.sodium_crypto_aead_chacha20poly1305_ietf_encrypt($value, $nonce, $nonce, $this->getKey());

            case static::CIPHER_X_CHACHA_IETF:
                return $nonce.sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($value, $nonce, $nonce, $this->getKey());

            default:
                return false;
        }
    }

    /**
     * Decrypt the given value.
     *
     * @param mixed $payload
     * @param bool  $unserialize
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     *
     * @return mixed
     */
    public function decrypt($payload, $unserialize = true)
    {
        $decoded = sodium_hex2bin($payload);

        $decrypted = $this->doDecrypt($decoded);

        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }

    /**
     * Decrypt the given string without unserialization.
     *
     * @param string $payload
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     *
     * @return string
     */
    public function decryptString($payload)
    {
        return $this->decrypt($payload, false);
    }

    /**
     * Run decryption on the given payload.
     *
     * @param $payload
     *
     * @return bool|string
     */
    protected function doDecrypt($payload)
    {
        $nonce = $this->extractNonce($payload);
        $ciphertext = $this->extractCipherText($payload);

        switch ($this->cipher) {
            case static::CIPHER_AES_256:
                return sodium_crypto_aead_aes256gcm_decrypt($ciphertext, $nonce, $nonce, $this->getKey());

            case static::CIPHER_CHACHA:
                return sodium_crypto_aead_chacha20poly1305_decrypt($ciphertext, $nonce, $nonce, $this->getKey());

            case static::CIPHER_CHACHA_IETF:
                return sodium_crypto_aead_chacha20poly1305_ietf_decrypt($ciphertext, $nonce, $nonce, $this->getKey());

            case static::CIPHER_X_CHACHA_IETF:
                return sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $nonce, $nonce, $this->getKey());

            default:
                return false;
        }
    }

    /**
     * Extract the nonce from an encrypted payload.
     *
     * @param $payload
     *
     * @return string
     */
    protected function extractNonce($payload)
    {
        return mb_substr($payload, 0, $this->getNonceLength(), '8bit');
    }

    /**
     * Extract the cipher text from an encrypted payload.
     *
     * @param $payload
     *
     * @return string
     */
    protected function extractCipherText($payload)
    {
        return mb_substr($payload, $this->getNonceLength(), mb_strlen($payload, '8bit'), '8bit');
    }
}
