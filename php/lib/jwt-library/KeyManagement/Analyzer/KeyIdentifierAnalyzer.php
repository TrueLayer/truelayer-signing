<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\KeyManagement\Analyzer;

use TrueLayer\Jose\Component\Core\JWK;


final class KeyIdentifierAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if (! $jwk->has('kid')) {
            $bag->add(Message::medium('The parameter "kid" should be added.'));
        }
    }
}