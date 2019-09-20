<?php

namespace Wizofgoz\Cryptographer;

use Illuminate\Support\ServiceProvider;
use Wizofgoz\Cryptographer\Console\KeyGenerateCommand;
use Wizofgoz\Cryptographer\Engines\OpenSslEngine;
use Wizofgoz\Cryptographer\Engines\SodiumEngine;
use Wizofgoz\Cryptographer\KeyDrivers\LocalKeyDriver;

class EncryptionServiceProvider extends ServiceProvider
{
    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->offerPublishing();
        $this->registerServices();
        $this->registerCommands();
    }

    /**
     * Setup the resource publishing groups for Cryptographer.
     *
     * @return void
     */
    protected function offerPublishing()
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../../../config/cryptographer.php' => config_path('cryptographer.php'),
            ], 'crypt-config');
        }
    }

    /**
     * Register Cryptographer's services in the container.
     *
     * @return void
     */
    protected function registerServices()
    {
        EncryptionManager::registerEngine('openssl', function () {
            return OpenSslEngine::class;
        });

        EncryptionManager::registerEngine('sodium', function () {
            return SodiumEngine::class;
        });

        KeyManager::registerDriver('local', function () {
            return LocalKeyDriver::class;
        });

        KeyManager::registerDriver('aws', function () {
            return LocalKeyDriver::class;
        });

        $this->app->singleton('encrypter', function ($app) {
            return new EncryptionManager($app);
        });

        $this->app->singleton('key-manager', function ($app) {
            return new KeyManager($app);
        });
    }

    /**
     * Register the Cryptographer Artisan command.
     *
     * @return void
     */
    protected function registerCommands()
    {
        $this->commands([KeyGenerateCommand::class]);
    }
}
