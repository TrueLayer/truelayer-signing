# truelayer/signing
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

$signer = Signer::signWithPem($kid, $pem, null);
$signer->method('POST')
    ->path('/path')
    ->header('Idempotency-Key', 'my-key')
    ->body('request body');
$signer->sign(); // signature output
```