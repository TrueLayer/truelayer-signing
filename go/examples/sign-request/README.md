# golang request signature example
Sends a signed request to `https://api.truelayer-sandbox.com/test-signature`.

## Run

Set environment variables:
* `ACCESS_TOKEN` A valid JWT access token for `payments` scope [docs](https://docs.truelayer.com/docs/retrieve-a-token-in-your-server).
* `KID` The certificate/key UUID for associated with your public key uploaded to console.truelayer.com.
* `PRIVATE_KEY` Private key PEM string that matches the `KID` & uploaded public key.
  Should have the same format as [this example private key](https://github.com/TrueLayer/truelayer-signing/blob/main/test-resources/ec512-private.pem).

```sh
$ go run main.go
```
