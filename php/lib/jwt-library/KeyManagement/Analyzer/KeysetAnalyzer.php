<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\KeyManagement\Analyzer;

use TrueLayer\Jose\Component\Core\JWKSet;

interface KeysetAnalyzer
{
    /**
     * This method will analyse the key set and add messages to the message bag if needed.
     */
    public function analyze(JWKSet $JWKSet, MessageBag $bag): void;
}
