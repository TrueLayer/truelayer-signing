<?php

\it('should normalise associative arrays of headers', function () {
    $headers = [
        'X-Header' => 'foo',
        'Another-Head' => 'bAr',
    ];

    $normalised = \TrueLayer\Signing\Util::normaliseHeaders($headers);

    \expect($normalised)->toBeArray();
    \expect($normalised)->toEqual([
        'Another-Head' => 'bAr',
        'X-Header' => 'foo',
    ]);
});

\it('should normalise arrays of header keys', function () {
    $headers = [
        'X-Header',
        'Foo-Header',
        'Another-Header',
    ];

    $normalised = \TrueLayer\Signing\Util::normaliseHeaderKeys($headers);

    \expect($normalised)->toBeArray();
    \expect($normalised)->toEqual([
        'Another-Header',
        'Foo-Header',
        'X-Header',
    ]);
});
