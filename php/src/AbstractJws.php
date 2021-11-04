<?php
declare(strict_types=1);

namespace TrueLayer\Signing;

use TrueLayer\Signing\Contracts\Jws as IJws;
use TrueLayer\Signing\Exceptions\RequestPathNotFoundException;

abstract class AbstractJws implements IJws
{
    protected string $requestMethod = 'POST';
    protected string $requestPath;
    protected string $requestBody = '';

    /**
     * @var array<string, string>
     */
    protected array $requestHeaders = [];

    /**
     * @param string $method
     * @return $this
     */
    public function method(string $method): self
    {
        $this->requestMethod = strtoupper($method);
        return $this;
    }

    /**
     * @param string $path
     * @return $this
     */
    public function path(string $path): self
    {
        $this->requestPath = $path;
        return $this;
    }

    /**
     * @param string $body
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
     * @return $this
     */
    public function header(string $key, string $value): self
    {
        $this->requestHeaders[$key] = $value;
        return $this;
    }

    /**
     * @param array<string, string> $headers
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
     * @return string
     * @throws RequestPathNotFoundException
     */
    public function buildPayload(): string
    {
        if (empty($this->requestPath)) {
            throw new RequestPathNotFoundException();
        }

        // Add the HTTP Method and Path
        $payload = "{$this->requestMethod} {$this->requestPath}\n";

        // Add the request headers
        foreach ($this->requestHeaders as $key => $value) {
            $payload .= "{$key}: {$value}\n";
        }

        // Add the request body
        $payload .= $this->requestBody;

        return $payload;
    }
}
