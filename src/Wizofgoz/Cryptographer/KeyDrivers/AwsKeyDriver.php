<?php

namespace Wizofgoz\Cryptographer\KeyDrivers;

use Aws\Kms\Exception\KmsException;
use Aws\Kms\KmsClient;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Wizofgoz\Cryptographer\Contracts\KeyDriver;

class AwsKeyDriver implements KeyDriver
{
    protected $awsClient;
    protected $key;
    protected $plaintextKey;
    protected $options;

    const KEY_STATE_ENABLED = 'Enabled';
    const KEY_STATE_DISABLED = 'Disabled';
    const KEY_STATE_PENDING_IMPORT = 'PendingImport';
    const KEY_STATE_PENDING_DELETION = 'PendingDeletion';
    const KEY_STATE_UNAVAILABLE = 'Unavailable';

    public function __construct($key, array $options)
    {
        $this->key = $key;
        $this->options = $options;

        if (!isset($this->options['master-key']) || $this->options['master-key'] === '') {
            throw new \RuntimeException('master key option is missing or empty');
        }

        $this->awsClient = new KmsClient([
            'profile' => $this->options['profile'] ?? 'default',
            'version' => 'latest',
            'region'  => self::resolveRegion($this->options),
        ]);

        $this->isKeyViable();
    }

    protected static function resolveRegion(array $options)
    {
        if (isset($options['region'])) {
            return $options['region'];
        }

        // if the master key is an ARN and region isn't set, we want to extract the region from it
        if (Str::startsWith($options['master-key'], 'arn')) {
            // ARNs are in one of the following formats:
            // arn:partition:service:region:account-id:resource-id
            // arn:partition:service:region:account-id:resource-type/resource-id
            // arn:partition:service:region:account-id:resource-type:resource-id
            // so we want the value at the [3] position
            $arnPieces = explode($options['master-key'], ':');
            $options['region'] = $arnPieces[3];
        }
    }

    protected function getKeyMeta()
    {
        $callback = function () {
            return $this->awsClient->describeKey([
                'KeyId' => $this->options['master-key'],
            ]);
        };

        if (app()->bound('cache')) {
            return Cache::remember("key_meta_{$this->key}", now()->addMinutes(30), $callback);
        }

        return $callback();
    }

    protected function isKeyViable()
    {
        $meta = $this->getKeyMeta();

        // check if the key has been deleted
        if ($meta['KeyState'] === self::KEY_STATE_PENDING_DELETION &&
            isset($meta['DeletionDate']) &&
            Carbon::parse($meta['DeletionDate'])->isPast()) {
            throw new \RuntimeException('master key has been deleted');
        }

        // check if the key has been rotated to a new value
        if ($meta['Origin'] === 'External' &&
            $meta['ExpirationModel'] == 'KEY_MATERIAL_EXPIRES' &&
            Carbon::parse($meta['ValidTo'])->isPast()) {
            throw new \RuntimeException('master key has been rotated and local key needs to be updated');
        }

        if ($meta['KeyState'] === self::KEY_STATE_DISABLED) {
            throw new \RuntimeException('master key is disabled');
        }

        if ($meta['KeyState'] === self::KEY_STATE_UNAVAILABLE) {
            throw new \RuntimeException('master key is unavailable');
        }

        return true;
    }

    /**
     * Generate a local data key encrypted with the given AWS KMS key.
     *
     * @param int   $length
     * @param array $additionalOptions
     *
     * @throws InvalidArgumentException
     * @throws KmsException
     *
     * @return string
     */
    public static function generateKey($length, array $additionalOptions = [])
    {
        if ($additionalOptions['master-key'] === '') {
            throw new InvalidArgumentException('option "master-key" is required for AWS KMS managed keys');
        }

        $client = new KmsClient([
           'profile' => 'default',
           'version' => 'latest',
           'region'  => self::resolveRegion($additionalOptions),
        ]);

        $result = $client->generateDataKeyWithoutPlaintext([
            'EncryptionContext' => $additionalOptions['context'] ?? [],
            'KeyId'             => $additionalOptions['master-key'],
            'NumberOfBytes'     => $length,
        ]);

        return $result['CiphertextBlob'];
    }

    /**
     * @return bool
     */
    public function isKeyRotatable(): bool
    {
        return true;
    }

    /**
     * Re-encrypt the key and return it.
     *
     * @return string
     */
    public function reEncrypt(): string
    {
        $result = $this->awsClient->reEncrypt([
            'CiphertextBlob'   => $this->key,
            'DestinationKeyId' => $this->options['master-key'],
        ]);

        return $result['CiphertextBlob'];
    }

    /**
     * Get the decrypted key.
     *
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
     * Decrypt the key cipher text.
     *
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
        if (extension_loaded('sodium')) {
            sodium_memzero($this->plaintextKey);
        } else {
            // override it with random data first to make sure it's unrecoverable
            $this->plaintextKey = random_bytes(20);
            $this->plaintextKey = null;
        }
    }
}
