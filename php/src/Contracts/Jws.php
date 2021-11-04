<?php
declare(strict_types=1);

namespace TrueLayer\Signing\Contracts;

interface Jws
{
    public function method(string $method): self;
    public function path(string $path): self;
    public function body(string $body): self;
    public function header(string $key, string $value): self;
    public function headers(array $headers): self;
    public function buildPayload(): string;
}