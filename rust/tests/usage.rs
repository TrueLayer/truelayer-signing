const PUBLIC_KEY: &str = include_str!("ec512-public.pem");
const PRIVATE_KEY: &str = include_str!("ec512-private.pem");
// we already know the public key, so the kid can be anything in these tests.
const KID: &str = "45fc75cf-5649-4134-84b3-192c2c78e990";

/// Sign a request body only and verify.
#[test]
fn body_signature() {
    let body = br#"{"abc":123}"#;

    let tl_signature = truelayer_request_signature::sign_with_pem(KID, PRIVATE_KEY)
        .body(body)
        .sign_body_only()
        .expect("sign_body");

    truelayer_request_signature::verify_with_pem(PUBLIC_KEY)
        .body(body)
        .verify(&tl_signature)
        .expect("verify");
}

#[test]
fn body_signature_mismatch() {
    let tl_signature = truelayer_request_signature::sign_with_pem(KID, PRIVATE_KEY)
        .body(br#"{"abc":123}"#)
        .sign_body_only()
        .expect("sign_body");

    truelayer_request_signature::verify_with_pem(PUBLIC_KEY)
        .body(br#"{"abc":124}"#) // different
        .verify(&tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn verify_body_static_signature() {
    let body = br#"{"abc":123}"#;
    let tl_signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2NDktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCJ9..AdDESSiHQVQSRFrD8QO6V8m0CWIfsDGyMOlipOt9LQhyG1lKjDR17crBgy_7TYi4ZQH--dyNtN9Nab3P7yFQzgqOALl8S-beevWYpnIMXHQCgrv-XpfNtenJTckCH2UAQIwR-pjV8XiTM1be1RMYpMl8qYTbCL5Bf8t_dME-1E6yZQEH";

    truelayer_request_signature::verify_with_pem(PUBLIC_KEY)
        .body(body)
        .verify(tl_signature)
        .expect("verify");
}

/// Sign method, path, headers & body and verify.
#[test]
fn full_request_signature() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_request_signature::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_request_signature::verify_with_pem(PUBLIC_KEY)
        .method("POST")
        .path(path)
        .require_header("Idempotency-Key")
        .header("X-Whatever", "aoitbeh")
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .verify(&tl_signature)
        .expect("verify");
}

#[test]
fn verify_full_request_static_signature() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";
    let tl_signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2NDktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGVhZGVycyI6IklkZW1wb3RlbmN5LUtleSJ9..AfhpFccUCUKEmotnztM28SUYgMnzPNfDhbxXUSc-NByYc1g-rxMN6HS5g5ehiN5yOwb0WnXPXjTCuZIVqRvXIJ9WAPr0P9R68ro2rsHs5HG7IrSufePXvms75f6kfaeIfYKjQTuWAAfGPAeAQ52PNQSd5AZxkiFuCMDvsrnF5r0UQsGi";

    truelayer_request_signature::verify_with_pem(PUBLIC_KEY)
        .method("POST")
        .path(path)
        .header("X-Whatever-2", "t2345d")
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .verify(tl_signature)
        .expect("verify");
}

#[test]
fn full_request_signature_method_mismatch() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_request_signature::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_request_signature::verify_with_pem(PUBLIC_KEY)
        .method("DELETE") // different
        .path(path)
        .header("X-Whatever", "aoitbeh")
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .verify(&tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn full_request_signature_path_mismatch() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_request_signature::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_request_signature::verify_with_pem(PUBLIC_KEY)
        .method("post")
        .path("/merchant_accounts/67b5b1cf-1d0c-45d4-a2ea-61bdc044327c/sweeping") // different
        .header("X-Whatever", "aoitbeh")
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .verify(&tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn full_request_signature_header_mismatch() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_request_signature::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_request_signature::verify_with_pem(PUBLIC_KEY)
        .method("post")
        .path(path)
        .header("X-Whatever", "aoitbeh")
        .header("Idempotency-Key", "something-else") // different
        .body(body)
        .verify(&tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn full_request_signature_body_mismatch() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_request_signature::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_request_signature::verify_with_pem(PUBLIC_KEY)
        .method("post")
        .path(path)
        .header("X-Whatever", "aoitbeh")
        .header("Idempotency-Key", idempotency_key)
        .body(br#"{"max_amount_in_minor":1234}"#) // different
        .verify(&tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn full_request_signature_missing_signature_header() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_request_signature::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_request_signature::verify_with_pem(PUBLIC_KEY)
        .method("post")
        .path(path)
        .header("X-Whatever", "aoitbeh")
        // missing Idempotency-Key
        .body(body)
        .verify(&tl_signature)
        .expect_err("verify should fail");
}

#[test]
fn full_request_signature_required_header_missing_from_signature() {
    let body = br#"{"currency":"GBP","max_amount_in_minor":5000000}"#;
    let idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_request_signature::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .sign()
        .expect("sign");

    truelayer_request_signature::verify_with_pem(PUBLIC_KEY)
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
    let idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
    let path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

    let tl_signature = truelayer_request_signature::sign_with_pem(KID, PRIVATE_KEY)
        .method("post")
        .path(path)
        .header("Idempotency-Key", idempotency_key)
        .header("X-Custom", "123")
        .body(body)
        .sign()
        .expect("sign");

    truelayer_request_signature::verify_with_pem(PUBLIC_KEY)
        .method("post")
        .path(path)
        .header("X-CUSTOM", "123") // different order & case, it's ok!
        .header("idempotency-key", idempotency_key) // different order & case, it's ok!
        .body(body)
        .verify(&tl_signature)
        .expect("verify");
}

#[test]
fn extract_jws_header() {
    let tl_signature = truelayer_request_signature::sign_with_pem(KID, PRIVATE_KEY)
        .method("delete")
        .path("/foo")
        .header("X-Custom", "123")
        .sign()
        .expect("sign");

    let jws_header =
        truelayer_request_signature::extract_jws_header(&tl_signature).expect("extract_jws_header");

    assert_eq!(jws_header.alg, "ES512");
    assert_eq!(jws_header.kid, KID);
    assert_eq!(jws_header.tl_version, "2");
    assert_eq!(jws_header.tl_headers, "X-Custom");
}
