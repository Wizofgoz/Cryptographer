<?php

use Wizofgoz\Cryptographer\Crypt;

if (!function_exists('ncrypt')) {
    /**
     * Encrypt the given value using the requested driver.
     *
     * @param mixed       $value
     * @param string|null $driver
     *
     * @return mixed
     */
    function ncrypt($value, $driver = null)
    {
        return Crypt::driver($driver)->encrypt($value);
    }
}

if (!function_exists('ncrypt')) {
    /**
     * Decrypt the given value using the requested driver.
     *
     * @param mixed       $value
     * @param string|null $driver
     *
     * @return mixed
     */
    function dcrypt($value, $driver = null)
    {
        return Crypt::driver($driver)->decrypt($value);
    }
}
