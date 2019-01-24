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
                    {--driver: Manually enter a driver to generate a key for}
                    {--schema: Manually enter a schema to generate a key for}
                    {--cipher: Manually enter a cipher to generate a key for}
                    {--env: Save the new key to env file under a custom name}
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

        $cipher = $this->option('cipher') ?? $this->laravel['config']["cryptographer.drivers.{$this->driver}.cipher"];
        $key = $this->generateRandomKey($cipher);

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
     * @param $cipher
     *
     * @return string
     */
    protected function generateRandomKey($cipher)
    {
        return 'base64:'.base64_encode(
            EncryptionManager::generateKey($this->laravel['config']["cryptographer.drivers.{$this->driver}.schema"], $cipher)
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
        file_put_contents($this->laravel->environmentFilePath(), preg_replace(
            $this->keyReplacementPattern(),
            "{$this->env}={$key}",
            file_get_contents($this->laravel->environmentFilePath())
        ));
    }

    /**
     * Get a regex pattern that will match env entry with any random key.
     *
     * @return string
     */
    protected function keyReplacementPattern()
    {
        $escaped = preg_quote('='.$this->laravel['config']["cryptographer.drivers.{$this->driver}.key"], '/');

        return "/^{$this->env}{$escaped}/m";
    }
}
