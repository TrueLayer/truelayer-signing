<?php

declare(strict_types=1);

namespace TrueLayer\Signing\Contracts;

interface Jws
{
    /**
     * @param string $method
     *
     * @return $this
     */
    public function method(string $method): self;

    /**
     * @param string $path
     *
     * @return $this
     */
    public function path(string $path): self;

    /**
     * @param string $body
     *
     * @return $this
     */
    public function body(string $body): self;

    /**
     * @param string $key
     * @param string $value
     *
     * @return $this
     */
    public function header(string $key, string $value): self;

    /**
     * @param array<string, string> $headers
     *
     * @return $this
     */
    public function headers(array $headers): self;

    /**
     * @param string[] $tlHeaders
     * @param bool     $withTrailingSlash
     *
     * @return string
     */
    public function buildPayload(array $tlHeaders, bool $withTrailingSlash = false): string;
}
