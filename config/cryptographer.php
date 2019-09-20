<?php

return [
    /*
     |--------------------------------------------------------------------------
     | Default Encryption Driver
     |--------------------------------------------------------------------------
     |
     | This is the name of the encryption driver that will be used by default so
     | expect it to be used for encrypting cookies and whatnot. If this is not
     | set, the first entry in the list of drivers will be used.
     |
     */

    'default-driver' => 'default',

    'default-key' => 'default',

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
            'key'    => 'default',
        ],

    ],

    /*
     |--------------------------------------------------------------------------
     | Encryption Keys
     |--------------------------------------------------------------------------
     |
     | This is a list of the encryption keys available to your application. Each
     | must have a unique name and include a management and value option. The management
     | option defines what driver to use when managing a key, and the value option
     | defines the current value of the key.
     |
     */

    'keys' => [
        'default' => [
            'management' => 'local',
            'value' => env('APP_KEY'),
        ],

        'kms' => [
            'management' => 'aws',
            'value' => 'encrypted_data_key',
            'region' => 'aws_region',
            'rotation' => true,
            'master-key' => 'key_id_for_making_data_key',
            'context' => [], // optional key/values for authenticating

        ]
    ],
];
