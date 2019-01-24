<?php

namespace Wizofgoz\Cryptographer;

use Illuminate\Support\ServiceProvider;
use Wizofgoz\Cryptographer\Console\KeyGenerateCommand;

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
            return OpenSslEncrypter::class;
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
