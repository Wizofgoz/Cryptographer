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
                    {--S|schema= : Manually enter a schema to generate a key for}
                    {--C|cipher= : Manually enter a cipher to generate a key for}
                    {--E|environment= : Save the new key to env file under a custom name}
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
        $this->env = $this->option('environment') ?? 'APP_KEY';

        $schema = $this->option('schema') ?? $this->laravel['config']["cryptographer.drivers.{$this->driver}.schema"];
        $cipher = $this->option('cipher') ?? $this->laravel['config']["cryptographer.drivers.{$this->driver}.cipher"];
        $key = $this->generateRandomKey($schema, $cipher);

        if ($this->option('show')) {
            return $this->line('<comment>'.$key.'</comment>');
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
     * @param string $schema
     * @param string $cipher
     *
     * @return string
     */
    protected function generateRandomKey($schema, $cipher)
    {
        return 'base64:'.base64_encode(
            EncryptionManager::generateKey($schema, $cipher)
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
