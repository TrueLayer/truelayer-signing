# Ruby request signature example

Sends a signed request to `https://api.truelayer-sandbox.com/test-signature`.

## Run

Set the following environment variables:

* `TRUELAYER_SIGNING_ACCESS_TOKEN` – a valid JWT access token for the `payments` scope (see our
    [docs](https://docs.truelayer.com/docs/retrieve-a-token-in-your-server)).
* `TRUELAYER_SIGNING_CERTIFICATE_ID` – the certificate/key UUID associated with your public key
    uploaded at [console.truelayer.com](https://console.truelayer.com).
* `TRUELAYER_SIGNING_PRIVATE_KEY` – the private key PEM string that matches the certificate ID of the
    uploaded public key. Should have the same format as [this example private
    key](https://github.com/TrueLayer/truelayer-signing/blob/main/test-resources/ec512-private.pem).

Install the required dependencies:

```sh
$ bundle
```

Execute the request-signing example script: 

```sh
$ ruby main.rb
```
