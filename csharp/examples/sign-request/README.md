# C# request signature example
Sends a signed request to `https://api.truelayer-sandbox.com/test-signature`.

## Run
Set environment variables:
* `ACCESS_TOKEN` A valid access token for `payments` scope [docs](https://docs.truelayer.com/docs/retrieve-a-token-in-your-server).
* `KID` The certificate/key ID for associated with your public key uploaded to console.truelayer.com.
* `PRIVATE_KEY` Private key PEM string that matches the `KID` & uploaded public key.

```sh
$ dotnet run
204 ✓
```
