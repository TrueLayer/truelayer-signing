<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Signature\Algorithm;



final class RS384 extends RSAPKCS1
{
    public function name(): string
    {
        return 'RS384';
    }

    protected function getAlgorithm(): string
    {
        return 'sha384';
    }
}
