use anyhow::{ensure, Context};
use axum::{
    body::Bytes,
    extract::Extension,
    http::{request, StatusCode},
    routing::post,
    Router,
};
use reqwest_middleware::ClientWithMiddleware;
use std::{net::SocketAddr, sync::Arc};
use tracing::{info, warn};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Setup a http client that will cache jwks responses according to cache-control headers
    let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
        .with(http_cache_reqwest::Cache(http_cache_reqwest::HttpCache {
            mode: http_cache_reqwest::CacheMode::Default,
            manager: Arc::new(http_cache_reqwest::MokaManager::default()),
            options: None,
        }))
        .build();

    let app = Router::new()
        .route(
            // Note: Webhook path can be whatever is configured, here a unique path
            // is used matching the README example signature.
            "/hook/d7a2c49d-110a-4ed2-a07d-8fdb3ea6424b",
            post(receive_hook),
        )
        .layer(Extension(client));

    info!("Starting server on :7000");

    axum::Server::bind(&SocketAddr::from(([127, 0, 0, 1], 7000)))
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn receive_hook(
    Extension(client): Extension<ClientWithMiddleware>,
    parts: request::Parts,
    body: Bytes,
) -> StatusCode {
    if let Err(err) = verify_hook(&client, &parts, &body).await {
        warn!("{err}");
        return StatusCode::UNAUTHORIZED;
    }

    // handle verified hook

    StatusCode::ACCEPTED
}

/// Returns `Ok(())` if the webhook `Tl-Signature` is valid.
async fn verify_hook(
    client: &ClientWithMiddleware,
    parts: &request::Parts,
    body: &Bytes,
) -> anyhow::Result<()> {
    let tl_signature = parts
        .headers
        .get("Tl-Signature")
        .context("missing Tl-Signature headers")?
        .to_str()
        .context("invalid non-string Tl-Signature")?;

    let jku = truelayer_signing::extract_jws_header(tl_signature)?
        .jku
        .context("jku missing")?;

    // ensure jku is an expected TrueLayer url
    ensure!(
        jku == "https://webhooks.truelayer.com/.well-known/jwks"
            || jku == "https://webhooks.truelayer-sandbox.com/.well-known/jwks",
        "Unpermitted jku {jku}"
    );

    // fetch jwks (cached according to cache-control headers)
    let jwks = client
        .get(jku)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    // verify signature using the jwks
    truelayer_signing::verify_with_jwks(&jwks)
        .method("POST")
        .path(parts.uri.path())
        .headers(
            parts
                .headers
                .iter()
                .map(|(h, v)| (h.as_str(), v.as_bytes())),
        )
        .body(body)
        .verify(tl_signature)?;

    Ok(())
}
