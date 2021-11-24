# TrueLayer/Signing
PHP library to produce & verify TrueLayer API request signatures.

## Installation
Require using composer:

```shell
$ composer require truelayer/signing
```

## Usage
```php
<?php
declare(strict_types=1);

use TrueLayer\Signing\Signer;

$signer = Signer::signWithPemFile('kid-value', '/path/to/privatekey');
$signer->method('POST')
    ->path('/path')
    ->header('Idempotency-Key', 'my-key')
    ->body('stringified request body');
    
$signature = $signer->sign();
```

You can use the library to verify signatures as well.
```php
<?php
declare(strict_types=1);

use TrueLayer\Signing\Exceptions\InvalidSignatureException;
use TrueLayer\Signing\Verifier;

$verifier = Verifier::verifyWithPemFile('/path/to/publickey');
$verifier->method('POST')
    ->path('/path')
    ->headers([
        'Idempotency-Key' => 'my-key',
        'Correlation-Id'  => 'my-correlation',
    ])
    ->requireHeaders([
        'User-Agent',
    ])
    ->body('stringified request body');

try {
    $verifier->verify('this is a fake signature');
} catch (InvalidSignatureException $e) {
    throw $e;
}
```