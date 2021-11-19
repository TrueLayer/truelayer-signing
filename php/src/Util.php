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
        // Sort the array
        if (!ksort($headers)) {
            throw new Exception('Could not sort the headers array.');
        }

        return $headers;
    }

    /**
     * @param string[] $headerKeys
     * @return string[]
     * @throws Exception
     */
    public static function normaliseHeaderKeys(array $headerKeys): array
    {
        // Sort the array
        if (!sort($headerKeys)) {
            throw new Exception('Could not sort the headers array.');
        }

        return $headerKeys;
    }

    /**
     * @param array $headers
     * @return array
     */
    public static function flattenHeaders(array $headers): array
    {
        $flattened = [];

        foreach($headers as $headerKey => $headerValues) {
            $flattened[$headerKey] = implode(',', $headerValues);
        }

        return $flattened;
    }
}