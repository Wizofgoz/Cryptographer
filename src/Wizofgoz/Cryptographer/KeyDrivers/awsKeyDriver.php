<?php

namespace Wizofgoz\Cryptographer\KeyDrivers;

use Aws\Kms\KmsClient;
use Wizofgoz\Cryptographer\Contracts\KeyDriver;

class awsKeyDriver implements KeyDriver
{
    protected $awsClient;
    protected $key;
    protected $plaintextKey;
    protected $masterKeyId;
    protected $options;

    public function __construct($key, array $options)
    {
        $this->key = $key;
        $this->options = $options;
        $this->awsClient = new KmsClient([
            'profile' => 'default',
            'version' => 'latest',
            'region'  => $this->options['region'],
        ]);
    }

    /**
     * @param $length
     *
     * @throws \Exception
     *
     * @return string
     */
    public static function generateKey($length)
    {
        return random_bytes($length);
    }

    /**
     * @return string
     */
    public function getKey()
    {
        if (!isset($this->plaintextKey)) {
            $this->plaintextKey = $this->decryptKey();
        }

        return $this->plaintextKey;
    }

    /**
     * @return string
     */
    protected function decryptKey()
    {
        $options = [
            'CiphertextBlob' => $this->key,
        ];

        if (isset($this->options['context'])) {
            $options['EncryptionContext'] = $this->options['context'];
        }

        $response = $this->awsClient->decrypt($options);

        return $response['Plaintext'];
    }

    /**
     * Clears plaintext version of key from memory.
     *
     * @throws \Exception
     *
     * @return void
     */
    public function clearMemory()
    {
        $this->plaintextKey = random_bytes(20);
        $this->plaintextKey = null;
    }
}
