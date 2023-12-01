<?php

namespace TrueLayer\Signing;

class Util
{
    /**
     * @param array<string, string> $headers
     *
     * @throws \Exception
     *
     * @return array<string, string>
     */
    public static function normaliseHeaders(array $headers): array
    {
        \ksort($headers);

        return $headers;
    }

    /**
     * @param string[] $headerKeys
     *
     * @throws \Exception
     *
     * @return string[]
     */
    public static function normaliseHeaderKeys(array $headerKeys): array
    {
        \sort($headerKeys);

        return $headerKeys;
    }

    /**
     * @param array<array<string>> $headers
     *
     * @return array<string, string>
     */
    public static function flattenHeaders(array $headers): array
    {
        $flattened = [];

        foreach ($headers as $headerKey => $headerValues) {
            $flattened[$headerKey] = \implode(',', $headerValues);
        }

        return $flattened;
    }
}
