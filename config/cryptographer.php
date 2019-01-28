<?php

return [
    /*
     |--------------------------------------------------------------------------
     | Default Encryption Driver
     |--------------------------------------------------------------------------
     |
     | This is name of the encryption driver that will be used by default so
     | expect it to be used for encrypting cookies and whatnot. If this is not
     | set, the first entry in the list of drivers will be used.
     |
     */

    'default' => 'default',

    /*
    |--------------------------------------------------------------------------
    | Encryption Drivers
    |--------------------------------------------------------------------------
    |
    | This is a list of the drivers available to your application. Driver
    | definitions must include the engine, cipher, and key options. The only
    | supported engines at this time are 'openssl' and 'sodium' but others can be
    | added via 3rd party packages.
    |
    */

    'drivers' => [

        'default' => [
            'engine' => 'openssl',
            'cipher' => \Wizofgoz\Cryptographer\Engines\OpenSslEngine::CIPHER_AES_128,
            'key'    => env('APP_KEY'),
        ],

    ],
];
