use axum::{
    extract::Host,
    extract::State,
    handler::HandlerWithoutStateExt,
    http::{StatusCode, Uri},
    response::Redirect,
    routing::{get, post},
    BoxError, Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use dotenv::dotenv;
use jsonwebtoken::{encode, Header as OtherHeader};
use once_cell::sync::Lazy;
use sqlx::{sqlite::SqlitePool, Pool, Sqlite};
use std::time::UNIX_EPOCH;
use std::{net::SocketAddr, path::PathBuf};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
mod data;
mod jwt;
mod keygen;

use crate::data::*;

static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    Keys::new(secret.as_bytes())
});

#[allow(dead_code)]
#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

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

    let ports = Ports {
        http: 7878,
        https: 3000,
    };

    // second (optional) server to read http requests and forward them to https
    tokio::spawn(redirect_http_to_https(ports));

    // configurar certificados
    let config = RustlsConfig::from_pem_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("cert.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("key.pem"),
    )
    .await
    .expect("Couldnt read TLS certificates. Make sure you read the README.md inside certs/");

    println!("TLS certificates read!");

    let sqlpool = SqlitePool::connect(std::env::var("DATABASE_URL")).await?;

    /* Routes:
       /api/now/encrypt   -> encrypt with a key relating to the current timestamp. Input: File to encrypt, Cipher used;       Outputs: Encrypted file and HMAC
       /api/now/decrypt   -> decrypt with a key relating to the current timestamp. Input: File to decrypt, HMAC, Cipher used; Outputs: Decrypted file
       /api/later/encrypt -> encrypt with a key relating to a later timestamp, provided by the user. Input: File, Timestamp, Cipher used
       /login     -> login route. Input: email and password
       /register  -> register route. Input: email and password
    */

    let app = Router::new()
        .route("/protected", get(protected))
        // .route("/api/now/encrypt", get(encrypt_now))
        // .route("/api/later/encrypt", get(encrypt_later))
        // .route("/api/now/decrypt", get(decrypt))
        .layer(axum::middleware::from_fn(jwt::refresh_middleware))
        .layer(axum::middleware::from_fn(keygen::keygen_middleware))
        .route("/login", post(login))
        .with_state(sqlpool)
        // .route("/register", get(register))
    ;

    println!("TLS Server started!");
    // run https server
    let addr = SocketAddr::from(([127, 0, 0, 1], ports.https));
    tracing::debug!("listening on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn protected(claims: Claims) -> Result<String, AuthError> {
    Ok(format!(
        "Welcome to the protected area :)\nYour data:\n{claims}",
    ))
}

async fn login(
    pool: State<Pool<Sqlite>>,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials
    if payload.email.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    let user = sqlx::query("SELECT * FROM users WHERE ? = email AND ? = password")
        .bind(payload.email)
        .bind(payload.client_secret)
        .fetch_one(pool)
        .await
        .expect("oopsies");

    let user = match user {
        Ok(u) => u,
        Err(_) => return Err(AuthError::WrongCredentials),
    };

    let now = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let mut claims = Claims {
        email: user.email,
        key: String::new(),
        key_timestamp: now + (60 * 5),
        exp: now as usize + (60 * 5), // 5 mins
    };

    claims.generate_key_from_now("testing");

    // Create the authorization token
    let token = encode(&OtherHeader::default(), &claims, &KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    // Send the authorized token
    Ok(Json(AuthBody::new(token)))
}

async fn register(
    pool: State<Pool<Sqlite>>,
    Json(payload): Json<RegisterPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials
    if payload.email.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    let mut conn = pool.acquire().await.expect("oopsies");
    match sqlx::query("SELECT * FROM users WHERE ? = email")
        .bind(payload.email)
        .fetch_one(conn)
        .await
    {
        Ok(u) => return Err(AuthError::DuplicateAccount),
        Err(_) => {}
    };

    let user =
        sqlx::query("INSERT INTO users (name, email, password, verified) VALUES (?, ?, ?, 1)")
            .bind(payload.name)
            .bind(payload.email)
            .bind(payload.client_secret)
            .execute(&mut *conn)
            .await?
            .last_insert_rowid();

    let now = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let mut claims = Claims {
        email: payload.email,
        key: String::new(),
        key_timestamp: now + (60 * 5),
        exp: now as usize + (60 * 5), // 5 mins
    };

    claims.generate_key_from_now("testing");

    // Create the authorization token
    let token = encode(&OtherHeader::default(), &claims, &KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    // Send the authorized token
    Ok(Json(AuthBody::new(token)))
}

#[allow(dead_code)]
async fn redirect_http_to_https(ports: Ports) {
    fn make_https(host: String, uri: Uri, ports: Ports) -> Result<Uri, BoxError> {
        let mut parts = uri.into_parts();

        parts.scheme = Some(axum::http::uri::Scheme::HTTPS);

        if parts.path_and_query.is_none() {
            parts.path_and_query = Some("/".parse().unwrap());
        }

        let https_host = host.replace(&ports.http.to_string(), &ports.https.to_string());
        parts.authority = Some(https_host.parse()?);

        Ok(Uri::from_parts(parts)?)
    }

    let redirect = move |Host(host): Host, uri: Uri| async move {
        match make_https(host, uri, ports) {
            Ok(uri) => Ok(Redirect::permanent(&uri.to_string())),
            Err(error) => {
                tracing::warn!(%error, "failed to convert URI to HTTPS");
                Err(StatusCode::BAD_REQUEST)
            }
        }
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], ports.http));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, redirect.into_make_service())
        .await
        .unwrap();
}
