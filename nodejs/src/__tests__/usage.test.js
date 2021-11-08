const { sign, verify } = require("../lib");

const PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
  + "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBVIVnghUzHmCEZ3HNjDmaZMJ7UwZf\n"
  + "av2SYcEtbDQc4uPhiEwWoYZMxzgvsz1vVGkusfTIjcXeCfDZ+xu9grRYt4kBo39z\n"
  + "w0i0j1rau4T7Bi+thc/VZpCyuwt63mZWcRs5PlQzpL34bBSXL5L6G9XUtXn8pXwU\n"
  + "GMhNDp5xVGbslRqTU8s=\n"
  + "-----END PUBLIC KEY-----\n"
const PRIVATE_KEY = "-----BEGIN EC PRIVATE KEY-----\n"
  + "MIHcAgEBBEIAVItA/A9H8WA0rOmDO5kq774be6noZ73xWJkbmzihkhtnYJ+eCQl4\n"
  + "G68ZFKildLuR2DElMBrNgJHY1TkL9hr7U9GgBwYFK4EEACOhgYkDgYYABAFUhWeC\n"
  + "FTMeYIRncc2MOZpkwntTBl9q/ZJhwS1sNBzi4+GITBahhkzHOC+zPW9UaS6x9MiN\n"
  + "xd4J8Nn7G72CtFi3iQGjf3PDSLSPWtq7hPsGL62Fz9VmkLK7C3reZlZxGzk+VDOk\n"
  + "vfhsFJcvkvob1dS1efylfBQYyE0OnnFUZuyVGpNTyw==\n"
  + "-----END EC PRIVATE KEY-----\n";
const KID = "45fc75cf-5649-4134-84b3-192c2c78e990";

describe('sign', () => {
  it("should sign a full request which can be successfully verified (verify won't throw)", () => {
    const body = '{"currency":"GBP","max_amount_in_minor":5000000}';
    const idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    const path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    const signature = sign({
      kid: KID,
      privateKeyPem: PRIVATE_KEY,
      method: "post",
      path,
      headers: { "Idempotency-Key": idempotencyKey },
      body,
    });

    verify({
      publicKeyPem: PUBLIC_KEY,
      signature,
      method: "POST",
      path,
      body,
      requiredHeaders: ["Idempotency-Key"],
      headers: {
        "X-Whatever-2": "yarshtarst",
        "Idempotency-Key": idempotencyKey,
      }
    });
  });
});
