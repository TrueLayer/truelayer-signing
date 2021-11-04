<?php

it('should normalise associative arrays of headers', function () {
    $headers = [
        'X-header' => 'foo',
        'aNother-head' => 'bAr',
    ];

    $normalised = \TrueLayer\Signing\Util::normaliseHeaders($headers);

    expect($normalised)->toBeArray();
    expect($normalised)->toEqual([
        'another-head' => 'bAr',
        'x-header' => 'foo',
    ]);
});

it('should normalise arrays of header keys', function () {
    $headers = [
        'X-Header',
        'fOOO-header',
        'another-hEader'
    ];

    $normalised = \TrueLayer\Signing\Util::normaliseHeaderKeys($headers);

    expect($normalised)->toBeArray();
    expect($normalised)->toEqual([
        'another-header',
        'fooo-header',
        'x-header',
    ]);
});