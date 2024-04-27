use axum::{
    body::Body,
    extract::{Host, Multipart, Request, State},
    handler::HandlerWithoutStateExt,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    BoxError, Extension, Form, Json, Router,
};

use axum_server::tls_rustls::RustlsConfig;
use dotenv::dotenv;
use jsonwebtoken::{encode, Header as OtherHeader};
use once_cell::sync::Lazy;
use ring::{digest, hmac, pbkdf2, rand};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::{sqlite::SqlitePool, Pool, Sqlite};
use std::time::UNIX_EPOCH;
use std::{net::SocketAddr, path::PathBuf};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use zip::write::SimpleFileOptions;
mod data;
mod jwt;
mod keygen;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use crate::data::*;
use base64::prelude::*;
use futures_util::stream::StreamExt;
use openssl::symm::{encrypt, Cipher};
use std::collections::HashMap;
use std::io::Write;

static IV: &[u8; 16] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";

fn hash_pass(p: String) -> String {
    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    argon2
        .hash_password(&p.into_bytes(), &salt)
        .expect("Hash failed!")
        .to_string()
}

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

    let sqlpool: Pool<Sqlite> =
        SqlitePool::connect(&std::env::var("DATABASE_URL").expect("oopsies"))
            .await
            .expect("oopsies");

    /* Routes:
       /api/now/encrypt   -> encrypt with a key relating to the current timestamp. Input: File to encrypt, Cipher used;       Outputs: Encrypted file and HMAC
       /api/now/decrypt   -> decrypt with a key relating to the current timestamp. Input: File to decrypt, HMAC, Cipher used; Outputs: Decrypted file
       /api/later/encrypt -> encrypt with a key relating to a later timestamp, provided by the user. Input: File, Timestamp, Cipher used
       /login     -> login route. Input: email and password
       /register  -> register route. Input: email and password
    */

    let app = Router::new()
        .route("/protected", get(protected))
        .route("/api/now/encrypt", post(encrypt_now))
        // .route("/api/later/encrypt", post(encrypt_later))
        // .route("/api/now/decrypt", post(decrypt))
        .layer(axum::middleware::from_fn(jwt::refresh_middleware))
        .layer(axum::middleware::from_fn(keygen::keygen_middleware))
        .route("/login", post(login))
        .route("/register", post(register))
        .layer(Extension(sqlpool));

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

/* cipher and hmac codes:
    1 -> AES-128-CBC
    2 -> AES-128-CTR

    1 -> HMAC-SHA256
    2 -> HMAC-SHA512
*/

async fn encrypt_now(claims: Claims, mut mp: Multipart) -> Response {
    use std::fs;
    let mut form = HashMap::new();

    while let Some(field) = mp.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        let data = field.bytes().await.unwrap();

        form.insert(name.clone(), data.clone());
        println!("Length of `{}` is {} bytes", name, data.len());
    }

    let file = form.clone().get("data").expect("No file (data)").to_vec();
    let cipher_bytes = form
        .clone()
        .get("cipher")
        .expect("Cipher not in form")
        .to_vec();

    let hmac_bytes = form.get("hmac").expect("Hmac not in form").to_vec();

    let c = u8::from_ne_bytes([cipher_bytes[0]]) - '0' as u8;
    let h = u8::from_ne_bytes([hmac_bytes[0]]) - '0' as u8;

    let (cipher, _hmac) = match (c, h) {
        (1, 1) => (Cipher::aes_128_cbc(), hmac::HMAC_SHA256),
        (1, 2) => (Cipher::aes_128_ecb(), hmac::HMAC_SHA512),
        (2, 1) => (Cipher::aes_128_ctr(), hmac::HMAC_SHA256),
        (2, 2) => (Cipher::aes_128_ctr(), hmac::HMAC_SHA512),
        _ => {
            println!("{}, {}", c, h);
            panic!()
        }
    };

    let key = &BASE64_STANDARD
        .decode(claims.key)
        .expect("Couldnt decode base64 key")[0..16];

    println!("Encrypting!\nKey length = {}", key.len());
    let ciphertext = encrypt(cipher, &key, Some(IV), file.as_slice()).unwrap();

    let mut buf = [0; 100_000];
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf[..]));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let filename = String::from_utf8(form.get("filename").expect("No filename in form").to_vec())
        .expect("Error creating string from UTF-8 bytes");

    let filename_enc = format!("{}.enc", filename.clone());
    zip.start_file(filename_enc, options)
        .expect("Couldnt create file inside zip");
    zip.write(ciphertext.as_slice())
        .expect("Couldnt write to file inside zip");

    let filename_hmac = format!("{}.hmac", filename.clone());
    zip.start_file(filename_hmac, options)
        .expect("Couldnt create file inside zip");
    zip.write(b"hmac")
        .expect("Couldnt write to file inside zip");

    zip.finish().expect("Couldnt finish zip");
    drop(zip);

    let headers = [
        (header::CONTENT_TYPE, "application/zip; charset=utf-8"),
        (
            header::CONTENT_DISPOSITION,
            &format!("attachment; filename=\"{}.zip\"", filename),
        ),
    ];
    (headers, buf).into_response()
}

async fn login(
    Extension(pool): Extension<SqlitePool>,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials
    if payload.email.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    let user = sqlx::query("SELECT * FROM users WHERE ? = email")
        .bind(payload.email)
        .fetch_one(&pool)
        .await;

    let user = match user {
        Ok(u) => u,
        Err(_) => return Err(AuthError::WrongCredentials),
    };

    let p: String = user.get("password");
    let p_hash = PasswordHash::new(p.as_ref()).expect("AA");
    if Argon2::default()
        .verify_password(&payload.client_secret.into_bytes(), &p_hash)
        .is_err()
    {
        return Err(AuthError::WrongCredentials);
    }

    let now = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let mut claims = Claims {
        email: user.get("email"),
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
    Extension(pool): Extension<SqlitePool>,
    Json(payload): Json<RegisterPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials
    if payload.email.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    let mut conn = pool.acquire().await.expect("oopsies");
    match sqlx::query("SELECT * FROM users WHERE ? = email")
        .bind(payload.email.clone())
        .fetch_one(&pool)
        .await
    {
        Ok(u) => return Err(AuthError::DuplicateAccount),
        Err(_) => {}
    };

    let _ = sqlx::query("INSERT INTO users (name, email, password, verified) VALUES (?, ?, ?, 1)")
        .bind(payload.name)
        .bind(payload.email.clone())
        .bind(hash_pass(payload.client_secret))
        .execute(&mut *conn)
        .await
        .expect("oopsies")
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
