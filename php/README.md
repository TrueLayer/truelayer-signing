# TrueLayer/Signing
PHP library to produce & verify TrueLayer API request signatures.
If you want to know more about how TrueLayer's signatures work, see [this documentation](./../request-signing-v2.md) for an explanation.

## Installation
Require using composer:

```shell
$ composer require truelayer/signing
```

## Usage

### Signing
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

You can also sign a PSR-7 request which will automatically compile the signature and add it to the `Tl-Signature` header.
```php
<?php
declare(strict_types=1);

use TrueLayer\Signing\Signer;

$signer = Signer::signWithPemFile('kid-value', '/path/to/privatekey');
$request = $signer->addSignatureHeader($request)
```

### Verifying
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

### Loading keys
Depending on your use case, the library allows various ways of instantiating the Signer and the Verifier.
```php
<?php
declare(strict_types=1);

use TrueLayer\Signing\Signer;
use TrueLayer\Signing\Verifier;

Signer::signWithPemFile('kid-value', '/path/to/privatekey', 'optional-passphrase');
Signer::signWithPem('kid-value', 'privatekey-pem-text', 'optional-passphrase');
Signer::signWithPemBase64('kid-value', 'base64-privatekey-pem-text', 'optional-passphrase');
Signer::signWithKey('kid-value', new \Jose\Component\Core\JWK());

Verifier::verifyWithPemFile('path/to/publickey');
Verifier::verifyWithPem('publickey-pem-text');
Verifier::verifyWithPemBase64('base64-publickey-pem-text');
Verifier::verifyWithJsonKeys(...$arrayOfMultipleJsonKeys);
Verifier::verifyWithKey(new \Jose\Component\Core\JWK());
```