<?php

namespace Wizofgoz\Cryptographer\Console;

use Illuminate\Console\Command;
use Illuminate\Console\ConfirmableTrait;
use Wizofgoz\Cryptographer\KeyManager;

class RotateKeyCommand extends Command
{
    use ConfirmableTrait;

    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'crypt:key:rotate
                    {key-name= : Key that is being rotated}
                    {--env= : Environment key to write updated key to}
                    {--show : Display the key instead of modifying files}
                    {--force : Force the operation to run when in production}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Re-encrypt the application key when the master key has expired';

    protected $name;

    protected $env;

    protected $keyManager;

    public function __construct(KeyManager $keyManager)
    {
        $this->keyManager = $keyManager;
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {
        $this->name = $this->argument('key-name');
        $this->env = $this->option('env') ?? 'APP_KEY';

        $key = $this->getRotatedKey();

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

        $this->laravel['config']["cryptographer.keys.{$this->name}.value"] = $key;

        $this->info("Application key {$this->name} rotated successfully.");
    }

    /**
     * @return string
     */
    protected function getRotatedKey()
    {
        $keyDriver = $this->keyManager->key($this->name);

        if (!$keyDriver->isKeyRotatable()) {
            throw new \RuntimeException("encryption key {$this->name} is not rotatable");
        }

        return 'base64:'.base64_encode($keyDriver->reEncrypt());
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
        $currentKey = $this->laravel['config']["cryptographer.keys.{$this->name}.value"];

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
        $escaped = preg_quote('='.$this->laravel['config']["cryptographer.keys.{$this->name}.value"], '/');
        $this->line("/^{$this->env}{$escaped}/m");

        return "/^{$this->env}{$escaped}/m";
    }
}
