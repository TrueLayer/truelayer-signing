<?php

namespace TrueLayer\Signing;

use Exception;

class Util
{
    /**
     * @param array<string, string> $headers
     * @return array<string, string>
     * @throws Exception
     */
    public static function normaliseHeaders(array $headers): array
    {
        // Lowercase all the keys
        $headersWithLowercaseKeys = array_change_key_case($headers, CASE_LOWER);

        // Sort the array
        if (!ksort($headersWithLowercaseKeys)) {
            throw new Exception('Could not sort the headers array.');
        }

        return $headersWithLowercaseKeys;
    }

    /**
     * @param string[] $headerKeys
     * @return string[]
     * @throws Exception
     */
    public static function normaliseHeaderKeys(array $headerKeys): array
    {
        // Lowercase all the headers
        $lowercaseKeys = array_map('strtolower', $headerKeys);

        // Sort the array
        if (!sort($lowercaseKeys)) {
            throw new Exception('Could not sort the headers array.');
        }

        return $lowercaseKeys;
    }
}