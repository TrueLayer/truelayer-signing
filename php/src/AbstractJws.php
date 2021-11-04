<?php

namespace TrueLayer\Signing;

use TrueLayer\Signing\Contracts\Jws as IJws;
use TrueLayer\Signing\Exceptions\RequestPathNotFoundException;

abstract class AbstractJws implements IJws
{
    protected string $request_method = 'POST';
    protected string $request_path;
    protected string $request_body = '';
    protected array $request_headers = [];

    public function method(string $method): self
    {
        $this->request_method = strtoupper($method);
        return $this;
    }

    public function path(string $path): self
    {
        $this->request_path = $path;
        return $this;
    }

    public function body(string $body): self
    {
        $this->request_body = $body;
        return $this;
    }

    public function header(string $key, string $value): self
    {
        $this->request_headers[$key] = $value;
        return $this;
    }

    public function headers(array $headers): self
    {
        foreach ($headers as $key => $value) {
            $this->header($key, $value);
        }
        return $this;
    }

    public function buildPayload(): string
    {
        if (empty($this->request_path)) {
            throw new RequestPathNotFoundException();
        }

        $payload = "{$this->request_method} {$this->request_path}\n";
        foreach ($this->request_headers as $key => $value) {
            $payload .= "{$key}: {$value}\n";
        }
        $payload .= $this->request_body;

        return $payload;
    }
}
