const assert = require('assert');
const { sign, verify, extractKid, SignatureError } = require("..");

// Use the same values as rust tests for cross-lang consistency assurance
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

describe('verify', () => {
  it('should not throw using the valid cross-lang static signature', () => {
    const body = '{"currency":"GBP","max_amount_in_minor":5000000}';
    const idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    const path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";
    const signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2NDktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGVhZGVycyI6IklkZW1wb3RlbmN5LUtleSJ9..AfhpFccUCUKEmotnztM28SUYgMnzPNfDhbxXUSc-NByYc1g-rxMN6HS5g5ehiN5yOwb0WnXPXjTCuZIVqRvXIJ9WAPr0P9R68ro2rsHs5HG7IrSufePXvms75f6kfaeIfYKjQTuWAAfGPAeAQ52PNQSd5AZxkiFuCMDvsrnF5r0UQsGi";

    verify({
      publicKeyPem: PUBLIC_KEY,
      signature,
      method: "POST",
      path,
      body,
      headers: {
        "X-Whatever-2": "foaulrsjth",
        "Idempotency-Key": idempotencyKey,
      }
    });
  });

  it('should throw using a signature with mismatched method', () => {
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

    assert.throws(
      () => verify({
        publicKeyPem: PUBLIC_KEY,
        signature,
        method: "DELETE", // different
        path,
        body,
        headers: {
          "X-Whatever-2": "foaulrsjth",
          "Idempotency-Key": idempotencyKey,
        }
      }),
      SignatureError);
  });

  it('should throw using a signature with mismatched path', () => {
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

    assert.throws(
      () => verify({
        publicKeyPem: PUBLIC_KEY,
        signature,
        method: "post",
        path: "/merchant_accounts/123/sweeping", // different
        body,
        headers: {
          "X-Whatever-2": "foaulrsjth",
          "Idempotency-Key": idempotencyKey,
        }
      }),
      SignatureError);
  });

  it('should throw using a signature with mismatched header', () => {
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

    assert.throws(
      () => verify({
        publicKeyPem: PUBLIC_KEY,
        signature,
        method: "post",
        path,
        body,
        headers: {
          "X-Whatever-2": "foaulrsjth",
          "Idempotency-Key": "37fa5dc5", // different
        }
      }),
      SignatureError);
  });

  it('should throw using a signature with mismatched body', () => {
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

    assert.throws(
      () => verify({
        publicKeyPem: PUBLIC_KEY,
        signature,
        method: "post",
        path,
        body: '{"max_amount_in_minor":5000000}', // different
        headers: {
          "X-Whatever-2": "foaulrsjth",
          "Idempotency-Key": idempotencyKey,
        }
      }),
      SignatureError);
  });

  it('should throw using a signature with missing signature header', () => {
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

    assert.throws(
      () => verify({
        publicKeyPem: PUBLIC_KEY,
        signature,
        method: "post",
        path,
        body,
        headers: {
          "X-Whatever-2": "foaulrsjth",
          // missing Idempotency-Key
        }
      }),
      SignatureError);
  });

  it('should verify header order/casing flexibly', () => {
    const body = '{"currency":"GBP","max_amount_in_minor":5000000}';
    const idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    const path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    const signature = sign({
      kid: KID,
      privateKeyPem: PRIVATE_KEY,
      method: "post",
      path,
      headers: {
        "Idempotency-Key": idempotencyKey,
        "X-Custom": "123",
      },
      body,
    });

    verify({
      publicKeyPem: PUBLIC_KEY,
      signature,
      method: "post",
      path,
      body,
      requiredHeaders: ["idempotency-KEY"], // different case, no worries!
      headers: {
        "X-CUSTOM": "123", // different order & case, it's ok!
        "X-Whatever-2": "foaulrsjth",
        "idempotency-key": idempotencyKey, // different order & case, chill it'll work!
      }
    });
  });

  it('should allow requiring that a given header is included in the signature', () => {
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

    assert.throws(
      () => verify({
        publicKeyPem: PUBLIC_KEY,
        signature,
        method: "post",
        path,
        body,
        requiredHeaders: ["X-Required"], // missing from signature
        headers: { "Idempotency-Key": idempotencyKey },
      }),
      SignatureError);
  });
});

describe('extractKid', () => {
  it('should produce a kid from a valid tl signature', () => {
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

    const kid = extractKid(signature);
    assert.equal(kid, KID);
  });
});
