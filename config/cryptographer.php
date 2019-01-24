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
    | definitions must include the schema, cipher, and key options. The only
    | supported schema at this time is 'openssl' but others can be
    | added via 3rd party packages.
    |
    */

    'drivers' => [

        'default' => [
            'schema' => 'openssl',
            'cipher' => \Wizofgoz\Cryptographer\OpenSslEncrypter::AES_128,
            'key'    => env('DEFAULT_ENCRYPTION_KEY'),
        ],

    ],
];
