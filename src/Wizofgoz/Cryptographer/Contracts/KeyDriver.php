<?php

namespace Wizofgoz\Cryptographer\Contracts;

interface KeyDriver
{
    public function getKey();

    public static function generateKey($length, array $additionalOptions = []);

    public function reEncrypt(): string;

    public function isKeyRotatable(): bool;

    public function clearMemory();
}
