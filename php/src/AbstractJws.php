<?php

declare(strict_types=1);

namespace TrueLayer\Signing;

use TrueLayer\Signing\Contracts\Jws as IJws;
use TrueLayer\Signing\Exceptions\RequestPathNotFoundException;
use TrueLayer\Signing\Exceptions\RequiredHeaderMissingException;

abstract class AbstractJws implements IJws
{
    /**
     * @var string
     */
    protected string $requestMethod = 'POST';

    /**
     * @var string
     */
    protected string $requestPath = '';

    /**
     * @var string
     */
    protected string $requestBody = '';

    /**
     * @var array<string, string>
     */
    protected array $requestHeaders = [];

    /**
     * @param string $method
     *
     * @return $this
     */
    public function method(string $method): self
    {
        $this->requestMethod = \strtoupper($method);

        return $this;
    }

    /**
     * @param string $path
     *
     * @return $this
     */
    public function path(string $path): self
    {
        $this->requestPath = $path;

        return $this;
    }

    /**
     * @param string $body
     *
     * @return $this
     */
    public function body(string $body): self
    {
        $this->requestBody = $body;

        return $this;
    }

    /**
     * @param string $key
     * @param string $value
     *
     * @return $this
     */
    public function header(string $key, string $value): self
    {
        $this->requestHeaders[\strtolower($key)] = $value;

        return $this;
    }

    /**
     * @param array<string, string> $headers
     *
     * @return $this
     */
    public function headers(array $headers): self
    {
        foreach ($headers as $key => $value) {
            $this->header($key, $value);
        }

        return $this;
    }

    /**
     * @param string[] $tlHeaders
     * @param bool     $withTrailingSlash
     *
     * @throws RequestPathNotFoundException
     * @throws RequiredHeaderMissingException
     *
     * @return string
     */
    public function buildPayload(array $tlHeaders, bool $withTrailingSlash = false): string
    {
        if (empty($this->requestPath)) {
            throw new RequestPathNotFoundException();
        }

        // The request path, with or without trailing slash
        $requestPath = \rtrim($this->requestPath, '/');
        if ($withTrailingSlash) {
            $requestPath .= '/';
        }

        // Add the HTTP Method and Path
        $payload = "{$this->requestMethod} {$requestPath}\n";

        // Add the request headers
        foreach ($tlHeaders as $tlHeaderKey) {
            $lcTlHeaderKey = \strtolower($tlHeaderKey);

            if (!isset($this->requestHeaders[$lcTlHeaderKey])) {
                throw new RequiredHeaderMissingException("Signature is missing the {$lcTlHeaderKey} header");
            }

            $headerValue = $this->requestHeaders[$lcTlHeaderKey];
            $payload .= "{$tlHeaderKey}: {$headerValue}\n";
        }

        // Add the request body
        $payload .= $this->requestBody;

        return $payload;
    }
}
