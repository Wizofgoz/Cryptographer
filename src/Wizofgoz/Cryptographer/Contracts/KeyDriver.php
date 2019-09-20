<?php

namespace Wizofgoz\Cryptographer\Contracts;

interface KeyDriver
{
    public function getKey();
    public static function generateKey($length);
    public function clearMemory();
}
