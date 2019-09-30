<?php

namespace Wizofgoz\Cryptographer\Console;

use Illuminate\Console\Command;
use Illuminate\Console\ConfirmableTrait;
use Wizofgoz\Cryptographer\EncryptionManager;

class KeyGenerateCommand extends Command
{
    use ConfirmableTrait;

    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'crypt:key:generate
                    {--D|driver= : Manually enter a driver to generate a key for}
                    {--E|engine= : Manually enter an engine to generate a key for}
                    {--C|cipher= : Manually enter a cipher to generate a key for}
                    {--K|key-driver= : Manually enter a key driver to use when generating a key}
                    {--k|aws-master-key= : For AWS KMS managed keys, this is the key ARN or ID that will be used for encrypting the local data key}
                    {--r|aws-region= : For AWS KMS managed keys, this is the region to use when looking up the master key. Defaults to region specified in --aws-master-key if it is an ARN and if not, the region specified by your credentials}
                    {--c|aws-context= : For AWS KMS managed keys, this is optional additional encryption context in the form of key-value pairs to apply when encrypting the local data key}
                    {--env= : Save the new key to env file under a custom name}
                    {--show : Display the key instead of modifying files}
                    {--force : Force the operation to run when in production}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Set the application key';

    protected $driver;

    protected $env;

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {
        $this->driver = $this->option('driver') ?? $this->getDefaultDriver();
        $this->env = $this->option('env') ?? 'APP_KEY';

        $engine = $this->option('engine') ?? $this->laravel['config']["cryptographer.drivers.{$this->driver}.engine"];
        $cipher = $this->option('cipher') ?? $this->laravel['config']["cryptographer.drivers.{$this->driver}.cipher"];

        if (($keyDriver = $this->option('key-driver')) === null) {
            $keyName = $this->laravel['config']["cryptographer.drivers.{$this->driver}.key"];
            $keyDriver = $this->option('key-driver') ?? $this->laravel['config']["cryptographer.keys.{$keyName}.management"];
        }

        $key = $this->generateRandomKey($engine, $keyDriver, $cipher);

        if ($this->option('show')) {
            $this->line('<comment>'.$key.'</comment>');
            return;
        }

        // Next, we will replace the application key in the environment file so it is
        // automatically setup for this developer. This key gets generated using a
        // secure random byte generator and is later base64 encoded for storage.
        if (!$this->setKeyInEnvironmentFile($key)) {
            return;
        }

        $this->laravel['config']["cryptographer.drivers.{$this->driver}.key"] = $key;

        $this->info('Application key set successfully.');
    }

    protected function getDefaultDriver()
    {
        if (isset($this->laravel['config']['cryptographer.default'])) {
            return $this->laravel['config']['cryptographer.default'];
        }

        return reset(array_keys($this->laravel['config']['cryptographer.drivers']));
    }

    /**
     * Generate a random key for the application.
     *
     * @param string $engine
     * @param string $keyDriver
     * @param string $cipher
     *
     * @return string
     */
    protected function generateRandomKey($engine, $keyDriver, $cipher)
    {
        $keyName = $this->laravel['config']["cryptographer.drivers.{$this->driver}.key"];
        $additionalOptions = [];

        if ($keyDriver === 'aws') {
            $additionalOptions['region'] = $this->option('aws-region') ?? $this->laravel['config']["cryptographer.keys.{$keyName}.region"];
            $additionalOptions['master-key'] = $this->option('aws-master-key') ?? $this->laravel['config']["cryptographer.keys.{$keyName}.master-key"];
            $additionalOptions['context'] = $this->option('aws-context') ?? $this->laravel['config']["cryptographer.keys.{$keyName}.context"];
        }

        return 'base64:'.base64_encode(
            EncryptionManager::generateKey($engine, $keyDriver, $cipher, $additionalOptions)
        );
    }

    /**
     * Set the application key in the environment file.
     *
     * @param string $key
     *
     * @return bool
     */
    protected function setKeyInEnvironmentFile($key)
    {
        $currentKey = $this->laravel['config']["cryptographer.drivers.{$this->driver}.key"];

        if (strlen($currentKey) !== 0 && (!$this->confirmToProceed())) {
            return false;
        }

        $this->writeNewEnvironmentFileWith($key);

        return true;
    }

    /**
     * Write a new environment file with the given key.
     *
     * @param string $key
     *
     * @return void
     */
    protected function writeNewEnvironmentFileWith($key)
    {
        $env = file_get_contents($this->laravel->environmentFilePath());

        if (strpos($env, $this->env) !== false) {
            $env = preg_replace(
                $this->keyReplacementPattern(),
                "{$this->env}={$key}",
                $env
            );
        } else {
            $env = "{$env}\n{$this->env}={$key}";
        }

        file_put_contents($this->laravel->environmentFilePath(), $env);
    }

    /**
     * Get a regex pattern that will match env entry with any random key.
     *
     * @return string
     */
    protected function keyReplacementPattern()
    {
        $escaped = preg_quote('='.$this->laravel['config']["cryptographer.drivers.{$this->driver}.key"], '/');
        $this->line("/^{$this->env}{$escaped}/m");

        return "/^{$this->env}{$escaped}/m";
    }
}
