<?php

namespace Wizofgoz\Cryptographer;

use Illuminate\Support\ServiceProvider;
use Wizofgoz\Cryptographer\Console\KeyGenerateCommand;
use Wizofgoz\Cryptographer\Schema\OpenSslSchema;
use Wizofgoz\Cryptographer\Schema\SodiumSchema;

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
        EncryptionManager::registerKeyGenerator('openssl', function () {
            return OpenSslSchema::class;
        });

        EncryptionManager::registerKeyGenerator('sodium', function () {
            return SodiumSchema::class;
        });

        $this->app->singleton('encrypter', function ($app) {
            return new EncryptionManager($app);
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
