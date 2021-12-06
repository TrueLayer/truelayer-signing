const PUBLIC_KEY: &[u8] = include_bytes!("../../test-resources/ec512-public.pem");
const PRIVATE_KEY: &[u8] = include_bytes!("../../test-resources/ec512-private.pem");
const KID: &str = "45fc75cf-5649-4134-84b3-192c2c78e990";

/// Sign a request body only and verify.
#[test]
fn body_signature() {
    let body = br#"{"abc":123}"#;

    let tl_signature = truelayer_signing::sign_with_pem(KID, PRIVATE_KEY)
        .body(body)
        .sign_body_only()
        .expect("sign_body");

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .allow_v1(true)
        .body(body)
        .verify(&tl_signature)
        .expect("verify");
}

#[test]
fn body_signature_mismatch() {
    let tl_signature = truelayer_signing::sign_with_pem(KID, PRIVATE_KEY)
        .body(br#"{"abc":123}"#)
        .sign_body_only()
        .expect("sign_body");

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .allow_v1(true)
        .body(br#"{"abc":124}"#) // different
        .verify(&tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn verify_body_static_signature() {
    let body = br#"{"abc":123}"#;
    let tl_signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2NDktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCJ9..AdDESSiHQVQSRFrD8QO6V8m0CWIfsDGyMOlipOt9LQhyG1lKjDR17crBgy_7TYi4ZQH--dyNtN9Nab3P7yFQzgqOALl8S-beevWYpnIMXHQCgrv-XpfNtenJTckCH2UAQIwR-pjV8XiTM1be1RMYpMl8qYTbCL5Bf8t_dME-1E6yZQEH";

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .allow_v1(true)
        .body(body)
        .verify(tl_signature)
        .expect("verify");
}

#[test]
fn verify_body_static_signature_not_allowed() {
    let body = br#"{"abc":123}"#;
    let tl_signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2NDktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCJ9..AdDESSiHQVQSRFrD8QO6V8m0CWIfsDGyMOlipOt9LQhyG1lKjDR17crBgy_7TYi4ZQH--dyNtN9Nab3P7yFQzgqOALl8S-beevWYpnIMXHQCgrv-XpfNtenJTckCH2UAQIwR-pjV8XiTM1be1RMYpMl8qYTbCL5Bf8t_dME-1E6yZQEH";

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        // v1 not allowed by default
        .body(body)
        .verify(tl_signature)
        .expect_err("verify should not be allowed");
}

/// Sign method, path, headers & body and verify.
#[test]
fn full_request_signature() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = b"idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_signing::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .method("POST")
        .path(path)
        .require_header("Idempotency-Key")
        .header("X-Whatever", b"aoitbeh")
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .verify(&tl_signature)
        .expect("verify");
}

/// Sign method, path & body and verify, headers are not required unless specified.
#[test]
fn full_request_signature_no_headers() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_signing::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .method("POST")
        .path(path)
        .header("X-Whatever", b"aoitbeh")
        .body(body)
        .verify(&tl_signature)
        .expect("verify");
}

#[test]
fn mismatched_signature_with_attached_valid_body() {
    // signature for `/bar` but with a valid jws-body pre-attached
    // if we run a simple jws verify on this unchanged it'll work!
    let tl_signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND\
      ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV\
      hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD\
      z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC\
      QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB\
      d2d3D17Wd9UA";

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .method("POST")
        .path("/foo") // not bar so should fail
        .body("{}".as_bytes())
        .verify(tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn mismatched_signature_with_attached_valid_body_trailing_dots() {
    // signature for `/bar` but with a valid jws-body pre-attached
    // if we run a simple jws verify on this unchanged it'll work!
    let tl_signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND\
      ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV\
      hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD\
      z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC\
      QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB\
      d2d3D17Wd9UA....";

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .method("POST")
        .path("/foo") // not bar so should fail
        .body("{}".as_bytes())
        .verify(tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn verify_full_request_static_signature() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = b"idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";
    let tl_signature = include_str!("../../test-resources/tl-signature.txt").trim();

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .method("POST")
        .path(path)
        .header("X-Whatever-2", b"t2345d")
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .verify(tl_signature)
        .expect("verify");
}

#[test]
fn full_request_signature_method_mismatch() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = b"idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_signing::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .method("DELETE") // different
        .path(path)
        .header("X-Whatever", b"aoitbeh")
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .verify(&tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn full_request_signature_path_mismatch() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = b"idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_signing::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .method("post")
        .path("/merchant_accounts/67b5b1cf-1d0c-45d4-a2ea-61bdc044327c/sweeping") // different
        .header("X-Whatever", b"aoitbeh")
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .verify(&tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn full_request_signature_header_mismatch() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = b"idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_signing::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .method("post")
        .path(path)
        .header("X-Whatever", b"aoitbeh")
        .header("Idempotency-Key", b"something-else") // different
        .body(body)
        .verify(&tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn full_request_signature_body_mismatch() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = b"idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_signing::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .method("post")
        .path(path)
        .header("X-Whatever", b"aoitbeh")
        .header("Idempotency-Key", idempotency_key)
        .body(br#"{"max_amount_in_minor":1234}"#) // different
        .verify(&tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn full_request_signature_missing_signature_header() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = b"idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_signing::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .method("post")
        .path(path)
        .header("X-Whatever", b"aoitbeh")
        // missing Idempotency-Key
        .body(body)
        .verify(&tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn full_request_signature_required_header_missing_from_signature() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = b"idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_signing::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .method("post")
        .path(path)
        .require_header("X-Required") // missing from signature
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .verify(&tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn flexible_header_case_order_verify() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = b"idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_signing::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .header("X-Custom", b"123")
        .body(body)
        .sign()
        .expect("sign");

    truelayer_signing::verify_with_pem(PUBLIC_KEY)
        .method("post")
        .path(path)
        .header("X-CUSTOM", b"123") // different order & case, it's ok!
        .header("idempotency-key", idempotency_key) // different order & case, it's ok!
        .body(body)
        .verify(&tl_signature)
        .expect("verify");
}

/// Note: Setting jku is only required for webhooks, so not a feature
/// needed by clients directly, or necessary in all langs.
#[test]
fn set_jku() {
    let tl_signature = truelayer_signing::sign_with_pem(KID, PRIVATE_KEY)
        .jku("https://webhooks.truelayer.com/.well-known/jwks")
        .sign()
        .expect("sign");

    let jws_header =
        truelayer_signing::extract_jws_header(&tl_signature).expect("extract_jws_header");

    assert_eq!(
        jws_header.jku.as_deref(),
        Some("https://webhooks.truelayer.com/.well-known/jwks")
    );
}

#[test]
fn extract_jws_header() {
    let tl_signature = include_str!("../../test-resources/webhook-signature.txt").trim();

    let jws_header =
        truelayer_signing::extract_jws_header(tl_signature).expect("extract_jws_header");

    assert_eq!(jws_header.alg, "ES512");
    assert_eq!(jws_header.kid, KID);
    assert_eq!(jws_header.tl_version, "2");
    assert_eq!(jws_header.tl_headers, "X-Tl-Webhook-Timestamp,Content-Type");
    assert_eq!(
        jws_header.jku.as_deref(),
        Some("https://webhooks.truelayer.com/.well-known/jwks")
    );
}

#[test]
fn verify_with_jwks() {
    let hook_signature = include_str!("../../test-resources/webhook-signature.txt").trim();
    let jwks = include_bytes!("../../test-resources/jwks.json");

    truelayer_signing::verify_with_jwks(jwks)
        .method("POST")
        .path("/tl-webhook")
        .header("x-tl-webhook-timestamp", b"2021-11-29T11:42:55Z")
        .header("content-type", b"application/json")
        .body(br#"{"event_type":"example","event_id":"18b2842b-a57b-4887-a0a6-d3c7c36f1020"}"#)
        .verify(hook_signature)
        .expect("verify");

    truelayer_signing::verify_with_jwks(jwks)
        .method("POST")
        .path("/tl-webhook")
        .header("x-tl-webhook-timestamp", b"2021-12-02T14:18:00Z") // different
        .header("content-type", b"application/json")
        .body(br#"{"event_type":"example","event_id":"18b2842b-a57b-4887-a0a6-d3c7c36f1020"}"#)
        .verify(hook_signature)
        .expect_err("verify should fail as header is different");
}
