<?php

namespace Wizofgoz\Cryptographer;

use Closure;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use InvalidArgumentException;
use RuntimeException;
use Wizofgoz\Cryptographer\Contracts\KeyDriver;
use Wizofgoz\Cryptographer\KeyDrivers\AwsKeyDriver;
use Wizofgoz\Cryptographer\KeyDrivers\LocalKeyDriver;

class KeyManager
{
    /**
     * @var \Closure[]
     */
    protected static $driverMap = [];

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
     * @var KeyDriver[]
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
     * Register the given key driver.
     *
     * @param string   $driver
     * @param \Closure $generator
     */
    public static function registerDriver($driver, Closure $generator)
    {
        static::$driverMap[$driver] = $generator;
    }

    /**
     * @param $driver
     * @param $length
     * @param array $additionalOptions
     *
     * @return mixed
     */
    public static function generateKey($driver, $length, array $additionalOptions = [])
    {
        if (!isset(static::$driverMap[$driver])) {
            throw new InvalidArgumentException("Key driver not found for [{$driver}] driver.");
        }

        /** @var KeyDriver $keyGenerator */
        $keyGenerator = (static::$driverMap[$driver])();

        if (!class_exists($keyGenerator)) {
            throw new RuntimeException("Key driver class [{$keyGenerator}] not found for [{$driver}] engine.");
        }

        return $keyGenerator::generateKey($length, $additionalOptions);
    }

    /**
     * Get a driver instance.
     *
     * @param string $key
     *
     * @throws \InvalidArgumentException
     *
     * @return KeyDriver
     */
    public function key($key = null)
    {
        $key = $key ?? $this->getDefaultKey();
        $config = $this->configuration($key);

        if (is_null($key)) {
            throw new InvalidArgumentException(sprintf(
                'Unable to resolve NULL driver for [%s].',
                static::class
            ));
        }

        // If the given driver has not been created before, we will create the instances
        // here and cache it so we can return it next time very quickly. If there is
        // already a driver created by this name, we'll just return that instance.
        if (!isset($this->drivers[$key])) {
            $this->drivers[$key] = $this->createDriver($config);
        }

        return $this->drivers[$key];
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
        $name = $name ?? $this->getDefaultKey();

        // To get the key driver configuration, we will just pull each of the
        // driver configurations and get the configurations for the given name.
        // If the driver doesn't exist, we'll throw an exception and bail.
        $keys = $this->app['config']['cryptographer.keys'];

        if (is_null($config = Arr::get($keys, $name))) {
            throw new InvalidArgumentException("Encryption key [{$name}] not configured.");
        }

        // If the key starts with "base64:", we will need to decode the key before handing
        // it off to the encrypter. Keys may be base-64 encoded for presentation and we
        // want to make sure to convert them back to the raw bytes before encrypting.
        if (Str::startsWith($key = $config['value'], 'base64:')) {
            $config['value'] = base64_decode(substr($key, 7));
        }

        return tap($config, function ($config) use ($name) {
            if (empty($config['value'])) {
                throw new RuntimeException(
                    "No value has been specified for encryption key [{$name}]."
                );
            }

            return $config;
        });
    }

    /**
     * Create an instance of the local key driver.
     *
     * @param array $config
     *
     * @return \Wizofgoz\Cryptographer\KeyDrivers\LocalKeyDriver
     */
    public function createLocalKeyDriver(array $config)
    {
        return new LocalKeyDriver($config['value'], $config);
    }

    /**
     * Create an instance of the AWS key driver.
     *
     * @param array $config
     *
     * @return \Wizofgoz\Cryptographer\KeyDrivers\AwsKeyDriver
     */
    public function createAwsKeyDriver(array $config)
    {
        return new AwsKeyDriver($config['value'], $config);
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
        $driver = $config['driver'];

        // First, we will determine if a custom driver creator exists for the given driver and
        // if it does not we will check for a creator method for the driver. Custom creator
        // callbacks allow developers to build their own "drivers" easily using Closures.
        if (isset($this->customCreators[$driver])) {
            return $this->callCustomCreator($driver, $config);
        } else {
            $method = 'create'.Str::studly($driver).'KeyDriver';

            if (method_exists($this, $method)) {
                return $this->$method($config);
            }
        }

        throw new InvalidArgumentException("Driver [$driver] not supported.");
    }

    /**
     * Call a custom driver creator.
     *
     * @param string $driver
     * @param array  $config
     *
     * @return mixed
     */
    protected function callCustomCreator($driver, $config)
    {
        return $this->customCreators[$driver]($config);
    }

    /**
     * Register a custom engine creator Closure.
     *
     * @param string   $driver
     * @param \Closure $callback
     *
     * @return $this
     */
    public function extend($driver, Closure $callback)
    {
        $this->customCreators[$driver] = $callback;

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
     * Get the default driver name.
     *
     * @return string
     */
    public function getDefaultKey()
    {
        // if a default isn't set in the config, use the first in the list of drivers
        $keys = array_keys($this->app['config']['cryptographer.keys']);

        return $this->app['config']['cryptographer.default-key'] ?? reset($keys);
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
        return $this->key()->$method(...$parameters);
    }
}
