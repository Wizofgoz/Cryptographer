<?php

namespace Wizofgoz\Cryptographer;

use Closure;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use InvalidArgumentException;
use RuntimeException;
use Wizofgoz\Cryptographer\Contracts\Engine;
use Wizofgoz\Cryptographer\Contracts\KeyDriver;
use Wizofgoz\Cryptographer\Engines\OpenSslEngine;
use Wizofgoz\Cryptographer\Engines\SodiumEngine;

class EncryptionManager
{
    /**
     * @var \Closure[]
     */
    protected static $engineMap = [];

    /**
     * The application instance.
     *
     * @var \Illuminate\Foundation\Application
     */
    protected $app;

    /**
     * The registered custom engine creators.
     *
     * @var \Closure[]
     */
    protected $customCreators = [];

    /**
     * The array of created "drivers".
     *
     * @var Engine[]
     */
    protected $drivers = [];

    /**
     * Create a new manager instance.
     *
     * @param \Illuminate\Foundation\Application $app
     *
     * @return void
     */
    public function __construct($app)
    {
        $this->app = $app;
    }

    /**
     * Get a driver instance.
     *
     * @param string $driver
     *
     * @throws \InvalidArgumentException
     *
     * @return Engine
     */
    public function driver($driver = null)
    {
        $driver = $driver ?: $this->getDefaultDriver();
        $config = $this->configuration($driver);

        if (is_null($driver)) {
            throw new InvalidArgumentException(sprintf(
                'Unable to resolve NULL driver for [%s].', static::class
            ));
        }

        // If the given driver has not been created before, we will create the instances
        // here and cache it so we can return it next time very quickly. If there is
        // already a driver created by this name, we'll just return that instance.
        if (!isset($this->drivers[$driver])) {
            $this->drivers[$driver] = $this->createDriver($config);
        }

        return $this->drivers[$driver];
    }

    /**
     * Get the configuration for a driver.
     *
     * @param string $name
     *
     * @throws \InvalidArgumentException
     *
     * @return array
     */
    protected function configuration($name)
    {
        $name = $name ?: $this->getDefaultDriver();

        // To get the database connection configuration, we will just pull each of the
        // connection configurations and get the configurations for the given name.
        // If the configuration doesn't exist, we'll throw an exception and bail.
        $drivers = $this->app['config']['cryptographer.drivers'];

        if (is_null($config = Arr::get($drivers, $name))) {
            throw new InvalidArgumentException("Encrypter [{$name}] not configured.");
        }

        // If the key starts with "base64:", we will need to decode the key before handing
        // it off to the encrypter. Keys may be base-64 encoded for presentation and we
        // want to make sure to convert them back to the raw bytes before encrypting.
        if (Str::startsWith($key = $config['key'], 'base64:')) {
            $config['key'] = base64_decode(substr($key, 7));
        }

        return tap($config, function ($config) use ($name) {
            if (empty($config['key'])) {
                throw new RuntimeException(
                    "No encryption key has been specified for driver [{$name}]."
                );
            }

            return $config;
        });
    }

    /**
     * Create a new driver instance.
     *
     * @param array $config
     *
     * @throws \InvalidArgumentException
     *
     * @return mixed
     */
    protected function createDriver($config)
    {
        $engine = $config['engine'];
        /** @var KeyManager $keyManager */
        $keyManager = $this->app->get('key-manager');
        $keyDriver = $keyManager->key($config['key']);

        // First, we will determine if a custom driver creator exists for the given driver and
        // if it does not we will check for a creator method for the driver. Custom creator
        // callbacks allow developers to build their own "drivers" easily using Closures.
        if (isset($this->customCreators[$engine])) {
            return $this->callCustomCreator($engine, $keyDriver, $config);
        } else {
            $method = 'create'.Str::studly($engine).'Engine';

            if (method_exists($this, $method)) {
                return $this->$method($keyDriver, $config);
            }
        }

        throw new InvalidArgumentException("Engine [$engine] not supported.");
    }

    /**
     * Call a custom driver creator.
     *
     * @param string    $engine
     * @param KeyDriver $keyDriver
     * @param array     $config
     *
     * @return mixed
     */
    protected function callCustomCreator($engine, KeyDriver $keyDriver, array $config)
    {
        return $this->customCreators[$engine]($keyDriver, $config);
    }

    /**
     * Create an instance of the OpenSSL encryption engine.
     *
     * @param KeyDriver $keyDriver
     * @param array     $config
     *
     * @return \Wizofgoz\Cryptographer\Engines\OpenSslEngine
     */
    public function createOpenSslEngine(KeyDriver $keyDriver, array $config)
    {
        return new OpenSslEngine($keyDriver, $config['cipher']);
    }

    /**
     * Create an instance of the Sodium encryption engine.
     *
     * @param KeyDriver $keyDriver
     * @param array     $config
     *
     * @return \Wizofgoz\Cryptographer\Engines\SodiumEngine
     */
    public function createSodiumEngine(KeyDriver $keyDriver, array $config)
    {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException('Sodium PHP extension is required to use the sodium engine.');
        }

        return new SodiumEngine($keyDriver, $config['cipher']);
    }

    /**
     * Register the given encryption engine.
     *
     * @param string   $engine
     * @param \Closure $generator
     */
    public static function registerEngine($engine, Closure $generator)
    {
        static::$engineMap[$engine] = $generator;
    }

    /**
     * Create a new encryption key for the cipher.
     *
     * @param string      $engine
     * @param string      $keyDriver
     * @param string|null $cipher
     * @param array       $additionalOptions
     *
     * @return string
     */
    public static function generateKey($engine, $keyDriver, $cipher = null, array $additionalOptions = [])
    {
        if (!isset(static::$engineMap[$engine])) {
            throw new InvalidArgumentException("Key generator not found for [{$engine}] engine.");
        }

        /** @var Engine $keyGenerator */
        $keyGenerator = (static::$engineMap[$engine])();

        if (!class_exists($keyGenerator)) {
            throw new RuntimeException("Key generator class [{$keyGenerator}] not found for [{$engine}] engine.");
        }

        return KeyManager::generateKey($keyDriver, $keyGenerator::getKeyLength($cipher), $additionalOptions);
    }

    /**
     * Encrypt the given value.
     *
     * @param mixed $value
     * @param bool  $serialize
     *
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     *
     * @return string
     */
    public function encrypt($value, $serialize = true)
    {
        return $this->driver()->encrypt($value, $serialize);
    }

    /**
     * Encrypt a string without serialization.
     *
     * @param string $value
     *
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     *
     * @return string
     */
    public function encryptString($value)
    {
        return $this->driver()->encryptString($value);
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
        return $this->driver()->decrypt($payload, $unserialize);
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
        return $this->driver()->decryptString($payload);
    }

    /**
     * Register a custom engine creator Closure.
     *
     * @param string   $engine
     * @param \Closure $callback
     *
     * @return $this
     */
    public function extend($engine, Closure $callback)
    {
        $this->customCreators[$engine] = $callback;

        return $this;
    }

    /**
     * Get all of the created "drivers".
     *
     * @return array
     */
    public function getDrivers()
    {
        return $this->drivers;
    }

    /**
     * Get the encryption key.
     *
     * @return string
     */
    public function getKey()
    {
        return $this->driver()->getKey();
    }

    /**
     * Get the default driver name.
     *
     * @return string
     */
    public function getDefaultDriver()
    {
        // if a default isn't set in the config, use the first in the list of drivers
        $keys = array_keys($this->app['config']['cryptographer.drivers']);
        return $this->app['config']['cryptographer.default-driver'] ?? reset($keys);
    }

    /**
     * Dynamically call the default driver instance.
     *
     * @param string $method
     * @param array  $parameters
     *
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        return $this->driver()->$method(...$parameters);
    }
}
