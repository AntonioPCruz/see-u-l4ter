use axum::{
    routing::{get, post},
    Json, Router,
};
use dotenv::dotenv;
use jsonwebtoken::{encode, Header as OtherHeader};
use once_cell::sync::Lazy;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
pub mod data;
mod jwt;

use crate::data::*;

static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    Keys::new(secret.as_bytes())
});

#[tokio::main]
async fn main() {
    dotenv().ok();
    println!(".env read!");

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "example_jwt=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = Router::new()
        .route("/protected", get(protected))
        .layer(axum::middleware::from_fn(jwt::refresh_middleware))
        .route("/authorize", post(authorize));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    println!("Server started!");
    axum::serve(listener, app).await.unwrap();
}

async fn protected(claims: Claims) -> Result<String, AuthError> {
    // Update the exp field
    Ok(format!(
        "Welcome to the protected area :)\nYour data:\n{claims}",
    ))
}

async fn authorize(Json(payload): Json<AuthPayload>) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }
    // Here you can check the user credentials from a database
    if payload.client_id != "foo" || payload.client_secret != "bar" {
        return Err(AuthError::WrongCredentials);
    }
    let claims = Claims {
        sub: "b@b.com".to_owned(),
        company: "ACME".to_owned(),
        exp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as usize
            + (60 * 5), // 5 mins
    };
    // Create the authorization token
    let token = encode(&OtherHeader::default(), &claims, &KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    // Send the authorized token
    Ok(Json(AuthBody::new(token)))
}
