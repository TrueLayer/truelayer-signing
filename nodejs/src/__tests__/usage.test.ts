import { sign, verify, extractJku, extractKid, SignatureError } from '../lib';
import { readFileSync } from 'fs';

// Use the same values as rust tests for cross-lang consistency assurance
const PUBLIC_KEY = readFileSync("../test-resources/ec512-public.pem", "utf8");
const PRIVATE_KEY = readFileSync("../test-resources/ec512-private.pem", "utf8");
const TL_SIGNATURE = readFileSync("../test-resources/tl-signature.txt", "utf8").trim();
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
    } as any);

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
    } as any);
  });
});

describe('verify', () => {
  it('should not throw using the valid cross-lang static signature', () => {
    const body = '{"currency":"GBP","max_amount_in_minor":5000000}';
    const idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    const path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    verify({
      publicKeyPem: PUBLIC_KEY,
      signature: TL_SIGNATURE,
      method: "POST",
      path,
      body,
      headers: {
        "X-Whatever-2": "foaulrsjth",
        "Idempotency-Key": idempotencyKey,
      }
    } as any);
  });

  it('should not throw using a signature with no headers', () => {
    const body = '{"currency":"GBP","max_amount_in_minor":5000000}';
    const path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    const signature = sign({
      kid: KID,
      privateKeyPem: PRIVATE_KEY,
      method: "post",
      path,
      body,
    } as any);

    verify({
      publicKeyPem: PUBLIC_KEY,
      signature,
      method: "post",
      path,
      body,
      headers: {
        "X-Whatever-2": "foaulrsjth",
      }
    } as any);
  });

  it('should throw using a mismatched signature that has an attached valid body', () => {
    // signature for `/bar` but with a valid jws-body pre-attached
    // if we run a simple jws verify on this unchanged it'll work!
    const signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND"
      + "ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV"
      + "hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD"
      + "z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC"
      + "QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB"
      + "d2d3D17Wd9UA";

    const fn = () => verify({
      publicKeyPem: PUBLIC_KEY,
      signature,
      method: "post",
      path: "/foo", // not /bar so should fail
      body: "{}"
    } as any);
    expect(fn).toThrow(new SignatureError("Invalid signature"));
  });

  it('should throw using a mismatched signature that has an attached valid body with trailing dots', () => {
    // signature for `/bar` but with a valid jws-body pre-attached
    // if we run a simple jws verify on this unchanged it'll work!
    const signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND"
      + "ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV"
      + "hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD"
      + "z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC"
      + "QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB"
      + "d2d3D17Wd9UA....";

    const fn = () => verify({
      publicKeyPem: PUBLIC_KEY,
      signature,
      method: "post",
      path: "/foo", // not /bar so should fail
      body: "{}"
    } as any);
    expect(fn).toThrow(new SignatureError("Invalid signature"));
  });

  it('should throw using a signature with mismatched method', () => {
    const body = '{"currency":"GBP","max_amount_in_minor":5000000}';
    const idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    const path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    const signature = sign({
      kid: KID,
      privateKeyPem: PRIVATE_KEY,
      method: "post" as any,
      path,
      headers: { "Idempotency-Key": idempotencyKey },
      body,
    } as any);

    const fn = () => verify({
      publicKeyPem: PUBLIC_KEY,
      signature,
      method: "DELETE", // different
      path,
      body,
      headers: {
        "X-Whatever-2": "foaulrsjth",
        "Idempotency-Key": idempotencyKey,
      }
    } as any)

    expect(fn).toThrow(new SignatureError("Invalid signature"));
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
    } as any);

    const fn = () => verify({
      publicKeyPem: PUBLIC_KEY,
      signature,
      method: "post",
      path: "/merchant_accounts/123/sweeping", // different
      body,
      headers: {
        "X-Whatever-2": "foaulrsjth",
        "Idempotency-Key": idempotencyKey,
      }
    } as any)

    expect(fn).toThrow(new SignatureError("Invalid signature"));
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
    } as any);

    const fn = () => verify({
      publicKeyPem: PUBLIC_KEY,
      signature,
      method: "post",
      path,
      body,
      headers: {
        "X-Whatever-2": "foaulrsjth",
        "Idempotency-Key": "37fa5dc5", // different
      }
    } as any);

    expect(fn).toThrow(new SignatureError("Invalid signature"));
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
    } as any);

    const fn = () => verify({
      publicKeyPem: PUBLIC_KEY,
      signature,
      method: "post",
      path,
      body: '{"max_amount_in_minor":5000000}', // different
      headers: {
        "X-Whatever-2": "foaulrsjth",
        "Idempotency-Key": idempotencyKey,
      }
    } as any);

    expect(fn).toThrow(new SignatureError("Invalid signature"));
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
    } as any);

    const fn = () => verify({
      publicKeyPem: PUBLIC_KEY,
      signature,
      method: "post",
      path,
      body,
      headers: {
        "X-Whatever-2": "foaulrsjth",
        // missing Idempotency-Key
      }
    } as any);

    expect(fn).toThrow(new SignatureError("Invalid signature"));
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
    } as any);

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
    } as any);
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
    } as any);

    const fn = () => verify({
      publicKeyPem: PUBLIC_KEY,
      signature,
      method: "post",
      path,
      body,
      requiredHeaders: ["X-Required"], // missing from signature
      headers: { "Idempotency-Key": idempotencyKey },
    } as any);

    expect(fn).toThrow(new SignatureError("signature is missing required header X-Required"));
  });

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
    } as any)

    const fn = () => verify({
      jwks: JWKS_JSON,
      signature: WEBHOOK_SIGNATURE,
      method: "post",
      path: "/tl-webhook",
      body: '{"event_type":"example","event_id":"18b2842b-a57b-4887-a0a6-d3c7c36f1020"}',
      headers: {
        "x-tl-webhook-timestamp": "2021-12-02T14:18:00Z", // different
        "content-type": "application/json"
      },
    } as any);

    expect(fn).toThrow(new SignatureError("Invalid signature"));
  });
});

describe('extractKid', () => {
  it('should produce a kid from a valid tl signature', () => {
    const kid = extractKid(TL_SIGNATURE);
    expect(kid).toEqual(KID);
  });
});

describe('extractJku', () => {
  it('should produce a jku from a valid tl signature', () => {
    const jku = extractJku(WEBHOOK_SIGNATURE);
    expect(jku).toEqual('https://webhooks.truelayer.com/.well-known/jwks');
  });
});
