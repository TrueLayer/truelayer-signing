const { sign, verify } = require("../lib");
const { readFileSync } = require("fs");

// Use the same values as rust tests for cross-lang consistency assurance
const PUBLIC_KEY = readFileSync("../test-resources/ec512-public.pem", "utf8");
const PRIVATE_KEY = readFileSync("../test-resources/ec512-private.pem", "utf8");
const WEBHOOK_SIGNATURE = readFileSync("../test-resources/webhook-signature.txt", "utf8").trim();
const JWKS_JSON = readFileSync("../test-resources/jwks.json", "utf8");
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

  it("should throw if using a non-string body", () => {
    const idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    const path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    const fn = () => sign({
      kid: KID,
      privateKeyPem: PRIVATE_KEY,
      method: "post",
      path,
      headers: { "Idempotency-Key": idempotencyKey },
      body: { "currency": "GBP", "max_amount_in_minor": 5000000 }, // wrong
    });

    expect(fn).toThrow(new Error("Invalid body 'object' type must be a string"));
  });
});

describe("verify", () => {
  it('should allow using jwks json instead of publicKeyPem', () => {
    verify({
      jwks: JWKS_JSON,
      signature: WEBHOOK_SIGNATURE,
      method: "post",
      path: "/tl-webhook",
      body: '{"event_type":"example","event_id":"18b2842b-a57b-4887-a0a6-d3c7c36f1020"}',
      headers: {
        "x-tl-webhook-timestamp": "2021-11-29T11:42:55Z",
        "content-type": "application/json"
      },
    });
  });
})
