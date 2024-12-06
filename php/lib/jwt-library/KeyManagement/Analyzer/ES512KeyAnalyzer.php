<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\KeyManagement\Analyzer;

use TrueLayer\Jose\Component\Core\Util\Ecc\Curve;
use TrueLayer\Jose\Component\Core\Util\Ecc\NistCurve;


final class ES512KeyAnalyzer extends ESKeyAnalyzer
{
    protected function getAlgorithmName(): string
    {
        return 'ES512';
    }

    protected function getCurveName(): string
    {
        return 'P-521';
    }

    protected function getCurve(): Curve
    {
        return NistCurve::curve521();
    }

    protected function getKeySize(): int
    {
        return 528;
    }
}
