use rand;
use std::env;
use uuid::Uuid;

// the base url to use
const TL_BASE_URL: &str = "https://api.truelayer-sandbox.com";

#[tokio::main]
async fn main() {
    // load env vars
    let kid = env::var("KID").expect("Missing env var KID");
    let access_token = env::var("ACCESS_TOKEN").expect("Missing env var ACCESS_TOKEN");
    let private_key = env::var("PRIVATE_KEY").expect("Missing env var PRIVATE_KEY");

    // create idemoptency key and body
    let idempotency_key = Uuid::new_v4().to_string();
    let body = format!("body-{}", rand::random::<u32>());

    // generate tl-signature
    let tl_signature = truelayer_signing::sign_with_pem(kid.as_str(), private_key.as_bytes())
        .method("POST")
        .path("/test-signature")
        .header("Idempotency-Key", idempotency_key.as_bytes())
        .header("X-Bar-Header", b"abc123")
        .body(body.as_bytes())
        .sign()
        .unwrap();

    // call `/test-signature` endpoint
    let client = reqwest::Client::new();
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

    // print result
    match response.error_for_status_ref() {
        Ok(res) => println!("{} ✓", res.status()),
        Err(err) => println!(
            "{}: {}",
            err.status().unwrap(),
            response.text().await.unwrap()
        ),
    }
}
