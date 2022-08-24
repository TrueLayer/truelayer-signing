# TrueLayer/Signing

PHP library to produce & verify TrueLayer API request signatures. If you want to know more about how TrueLayer's
signatures work, see [this documentation](./../request-signing-v2.md) for an explanation.

## Installation

Require using composer:

```shell
$ composer require truelayer/signing
```

## Usage

### Signing

First, create a Signer instance, using one of the following methods:

```php
use TrueLayer\Signing\Signer;

$signer = Signer::signWithPemFile('kid-value', '/path/to/privatekey');
$signer = Signer::signWithPem('kid-value', $pemContents);
$signer = Signer::signWithPemBase64('kid-value', $pemContentsBase64Encoded);
$signer = Signer::signWithKey('kid-value', new \Jose\Component\Core\JWK());
```

Then you can use it to create signatures:

```php
use TrueLayer\Signing\Signer;

$signature = $signer->method('POST')
    ->path('/path') // The api path
    ->header('Idempotency-Key', 'my-key') // The idempotency key you must send with your request
    ->body('stringified request body')
    ->sign();    
```

You can also sign a PSR-7 request which will automatically compile the signature and add it to the `Tl-Signature`
header.

```php
use TrueLayer\Signing\Signer;

$request = $signer->addSignatureHeader($request)
```

### Verifying

First, retrieve the public keys:

- for sandbox: https://webhooks.truelayer-sandbox.com/.well-known/jwks
- for production: https://webhooks.truelayer.com/.well-known/jwks

Example using the [Guzzle](https://docs.guzzlephp.org/en/stable/) library:

```php
use TrueLayer\Signing\Verifier;
use GuzzleHttp\Client;

// Note: you should add error handling as appropriate
$httpClient = new Client();
$response = $httpClient->get('https://webhooks.truelayer-sandbox.com/.well-known/jwks')->getBody()->getContents();
$keys = json_decode($response, true)['keys'];

$verifier = Verifier::verifyWithJsonKeys(...$keys); // Note the spread operator, it's important.
```

Then you can use it to verify the signature you receive in your webhook under the `tl-signature` header:

```php
$verifier
    ->path('/path') // Should be your webhook path, for example $_SERVER['REQUEST_URI']
    ->headers($headers) // All headers you receive. Header names can be in any casing.
    ->body('stringified request body'); // For example file_get_contents('php://input');

try {
    $verifier->verify($headers['tl-signature']);
} catch (InvalidSignatureException $e) {
    throw $e; // Handle invalid signature. You should not use this request's data.
}
```