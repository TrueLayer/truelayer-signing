use std::env;
use uuid::Uuid;

// the base url to use
const TL_BASE_URL: &str = "https://api.truelayer-sandbox.com";

#[tokio::main]
async fn main() {
    // Read required env vars
    let kid = env::var("KID").expect("Missing env var KID");
    let access_token = env::var("ACCESS_TOKEN").expect("Missing env var ACCESS_TOKEN");
    let private_key = env::var("PRIVATE_KEY").expect("Missing env var PRIVATE_KEY");

    // A random body string is enough for this request as `/test-signature` endpoint does not
    // require any schema, it simply checks the signature is valid against what's received.
    let body = format!("body-{}", rand::random::<u32>());

    let idempotency_key = Uuid::new_v4().to_string();

    // Generate tl-signature
    let tl_signature = truelayer_signing::sign_with_pem(kid.as_str(), private_key.as_bytes())
        .method("POST") // as we're sending a POST request
        .path("/test-signature") // the path of our request
        // Optional: /test-signature does not require any headers, but we may sign some anyway.
        // All signed headers *must* be included unmodified in the request.
        .header("Idempotency-Key", idempotency_key.as_bytes())
        .header("X-Bar-Header", b"abc123")
        .body(body.as_bytes()) // body of our request
        .sign()
        .unwrap();

    let client = reqwest::Client::new();
    // Request body & any signed headers *must* exactly match what was used to generate the signature.
    let response = client
        .post(format!("{}/test-signature", TL_BASE_URL))
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Idempotency-Key", idempotency_key)
        .header("X-Bar-Header", "abc123")
        .header("Tl-Signature", tl_signature)
        .body(body)
        .send()
        .await
        .unwrap();

    let status = response.status();
    let response_body = match status.is_success() {
        true => String::from("✓"),
        false => response.text().await.unwrap(),
    };

    // 204 means success
    // 401 means either the access token is invalid, or the signature is invalid.
    println!("{} {}", status.as_u16(), response_body);
}
