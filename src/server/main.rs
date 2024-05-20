use axum::Router;
use axum::{
    extract::{Host, Multipart},
    handler::HandlerWithoutStateExt,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    BoxError, Extension, Json,
};
use hmac::Mac;
use log::{info, warn};

use axum_server::tls_rustls::RustlsConfig;
use dotenv::dotenv;
use jsonwebtoken::{encode, Header as OtherHeader};
use once_cell::sync::Lazy;
use reqwest::Method;
use serde_json::json;
use sha2::{Sha256, Sha512};
use sqlx::Row;
use sqlx::{sqlite::SqlitePool, Pool, Sqlite};
use std::{io::Read, time::UNIX_EPOCH};
use std::{net::SocketAddr, path::PathBuf};
use tower_http::cors::CorsLayer;
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
use chrono::TimeZone;
use openssl::symm::{decrypt, encrypt, Cipher};
use std::collections::HashMap;
use std::io::{Cursor, Write};

use ::hmac::{digest::MacError, Hmac};

pub const FORMAT_STR: &str = "%Y-%m-%d-%H:%M";

type THmacSha256 = Hmac<Sha256>;
type THmacSha512 = Hmac<Sha512>;

enum HashAlgorithms {
    HmacSha256,
    HmacSha512,
}

impl HashAlgorithms {
    fn verify(&self, key: &[u8], d1: &[u8], d2: &[u8]) -> Result<(), MacError> {
        match self {
            HashAlgorithms::HmacSha256 => {
                let mut mac = THmacSha256::new_from_slice(key).expect("Expected a valid hmac");
                mac.update(d1);
                mac.verify(d2.into())
            }
            HashAlgorithms::HmacSha512 => {
                let mut mac = THmacSha512::new_from_slice(key).expect("Expected a valid hmac");
                mac.update(d1);
                mac.verify(d2.into())
            }
        }
    }
    fn hash(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithms::HmacSha256 => {
                let mut mac = THmacSha256::new_from_slice(key).unwrap();
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            HashAlgorithms::HmacSha512 => {
                let mut mac = THmacSha512::new_from_slice(key).unwrap();
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }
}

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
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{} {} {}] {}",
                humantime::format_rfc3339_seconds(std::time::SystemTime::now()),
                record.level(),
                record.target(),
                message
            ))
        })
        .level(log::LevelFilter::Debug)
        .chain(std::io::stdout())
        .chain(fern::log_file("output.log").expect("Cant create log file"))
        .apply()
        .expect("Output err");

    dotenv().ok();
    info!(target: "server_events", "Server starting...");
    info!(target: "server_events", ".env read!");

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

    info!("TLS certificates read!");

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

    let cors = CorsLayer::new()
        .allow_methods(vec![Method::GET, Method::POST])
        .allow_headers(tower_http::cors::Any)
        .allow_origin(tower_http::cors::Any);

    let app = Router::new()
        .route("/protected", get(protected))
        .route("/profile", get(profile))
        .route("/api/now/encrypt", post(encrypt_now))
        .route("/api/now/decrypt", post(decrypt_now))
        .route("/api/later/encrypt", post(encrypt_later))
        .route("/api/old/gen", post(old_gen))
        .route("/api/now/gen", post(gen))
        .layer(axum::middleware::from_fn(jwt::refresh_middleware))
        .layer(axum::middleware::from_fn(keygen::keygen_middleware))
        .route("/login", post(login))
        .route("/register", post(register))
        .layer(Extension(sqlpool))
        .layer(cors);

    info!("Server started!");
    // run https server
    let addr = SocketAddr::from(([127, 0, 0, 1], ports.https));
    info!("Listening on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn protected(claims: Claims) -> Result<Json<Claims>, AuthError> {
    Ok(Json(claims))
}

async fn profile(
    Extension(pool): Extension<SqlitePool>,
    claims: Claims,
) -> Result<Json<Profile>, AuthError> {
    let user = sqlx::query("SELECT * FROM users WHERE ? = email")
        .bind(claims.email.clone())
        .fetch_one(&pool)
        .await
        .expect("oopsies");

    Ok(Json(Profile {
        name: user.get("name"),
        email: user.get("email"),
    }))
}

/* cipher and hmac codes:
    1 -> AES-128-CBC
    2 -> AES-128-CTR

    1 -> HMAC-SHA256
    2 -> HMAC-SHA512
*/

async fn encrypt_aux(
    claims: Claims,
    file: Vec<u8>,
    cipher_bytes: Vec<u8>,
    hmac_bytes: Vec<u8>,
    filename: String,
    key: &[u8],
) -> Response {
    let c = u8::from_ne_bytes([cipher_bytes[0]]) - '0' as u8;
    let h = u8::from_ne_bytes([hmac_bytes[0]]) - '0' as u8;

    let cipher = match c {
        1 => Cipher::aes_128_cbc(),
        2 => Cipher::aes_128_ctr(),
        _ => {
            println!("{}, {}", c, h);
            panic!()
        }
    };

    let hmac = match h {
        1 => HashAlgorithms::HmacSha256, //HmacSha256
        2 => HashAlgorithms::HmacSha512, //HmacSha512
        _ => {
            println!("{}, {}", c, h);
            panic!()
        }
    };

    info!(target: "encrypting_events", "User ({}): Key used for cipher = {}", claims.email, BASE64_STANDARD.encode(&key[0..16]));
    info!(target: "encrypting_events", "User ({}): Key used for hmacs = {}", claims.email, BASE64_STANDARD.encode(&key[16..32]));
    info!(target: "encrypting_events", "User ({}): Encryption starting", claims.email);

    let ciphertext =
        encrypt(cipher, &key[0..16], Some(IV), file.as_slice()).expect("Encrypting error");
    let hmac_result = hmac.hash(&key[16..32], ciphertext.as_slice());

    info!(target: "encrypting_events", "User ({}): Encryption complete with ciphermode {}, HMAC complete with hashing algorithm {}", claims.email, data::ciphercode_to_string(c), data::hmaccode_to_string(h));

    let metadata = format!("cipher = {}\nhmac = {}\n", c, h);
    let hmac_metadata = HashAlgorithms::HmacSha256.hash(&key[16..32], metadata.as_bytes());

    info!(target: "encrypting_events", "User ({}): Metadata created and metadata HMAC complete. cipher = {}, hmac = {}", claims.email, c, h);


    let mut buf = vec![0; ciphertext.len()+1000];
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf.as_slice()[..]));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    let filename_enc = format!("{}.enc", filename.clone());
    zip.start_file(filename_enc, options)
        .expect("Couldnt create file inside zip");
    zip.write(ciphertext.as_slice())
        .expect("Couldnt write to file inside zip");

    info!(target: "encrypting_events", "User ({}): Ciphertext stored inside zip", claims.email);

    let filename_hmac = format!("{}.hmac", filename.clone());
    zip.start_file(filename_hmac, options)
        .expect("Couldnt create file inside zip");
    zip.write(hmac_result.as_slice())
        .expect("Couldnt write to file inside zip");

    info!(target: "encrypting_events", "User ({}): Ciphertext HMAC stored inside zip", claims.email);

    zip.start_file("see-u-l4ter.options", options)
        .expect("Couldnt create file inside zip");
    zip.write(metadata.as_bytes())
        .expect("Couldnt write to file inside zip");

    info!(target: "encrypting_events", "User ({}): Metadata stored inside zip", claims.email);

    zip.start_file("see-u-l4ter.hmac", options)
        .expect("Couldnt create file inside zip");
    zip.write(&hmac_metadata)
        .expect("Couldnt write to file inside zip");

    info!(target: "encrypting_events", "User ({}): Metadata HMAC stored inside zip", claims.email);

    zip.finish().expect("Couldnt finish zip");
    drop(zip);

    info!(target: "encrypting_events", "User ({}): Zip finished. Sending now.", claims.email);

    let headers = [
        (header::CONTENT_TYPE, "application/zip; charset=utf-8"),
        (
            header::CONTENT_DISPOSITION,
            &format!("attachment; filename=\"{}.zip\"", filename),
        ),
    ];
    (headers, buf).into_response()
}

async fn encrypt_now(claims: Claims, mut mp: Multipart) -> Response {
    info!(target: "encrypting_events", "User ({}): Requested an encryption.", claims.email);
    let mut form = HashMap::new();

    while let Some(field) = mp.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        let data = field.bytes().await.unwrap();

        form.insert(name.clone(), data.clone());
    }

    let file = form.clone().get("data").expect("No file (data)").to_vec();
    let cipher_bytes = form
        .clone()
        .get("cipher")
        .expect("Cipher not in form")
        .to_vec();

    let hmac_bytes = form.get("hmac").expect("Hmac not in form").to_vec();

    let filename = String::from_utf8(form.get("filename").expect("No filename in form").to_vec())
        .expect("Error creating string from UTF-8 bytes");

    info!(target: "encrypting_events", "User ({}): Form is okay.", claims.email);

    info!(target: "encrypting_events", "User ({}): Whole key = {}", claims.email, claims.key);

    let key = &BASE64_STANDARD
        .decode(&claims.key)
        .expect("Couldnt decode base64 key");

    encrypt_aux(claims, file, cipher_bytes, hmac_bytes, filename, key).await
}

async fn encrypt_later(mut claims: Claims, mut mp: Multipart) -> Response {
    info!(target: "encrypting_events", "User ({}): Requested an encryption for later.", claims.email);
    let mut form = HashMap::new();

    while let Some(field) = mp.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        let data = field.bytes().await.unwrap();

        form.insert(name.clone(), data.clone());
    }

    let file = form.clone().get("data").expect("No file (data)").to_vec();
    let cipher_bytes = form
        .clone()
        .get("cipher")
        .expect("Cipher not in form")
        .to_vec();

    let hmac_bytes = form.get("hmac").expect("Hmac not in form").to_vec();

    let filename = String::from_utf8(form.get("filename").expect("No filename in form").to_vec())
        .expect("Error creating string from UTF-8 bytes");

    info!(target: "encrypting_events", "User ({}): Form is okay.", claims.email);

    let dt = form
        .clone()
        .get("timestamp")
        .expect("No timestamp")
        .to_vec();
    let t = String::from_utf8(dt).expect("Invalid timestamp");

    let date = if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(&t, FORMAT_STR) {
        let utc_datetime = chrono::Utc.from_utc_datetime(&naive);
        if utc_datetime < chrono::Utc::now() {
            info!(target: "encrypting_events", "User ({}): Date received is before current timestamp.", claims.email);
            return ApiError::InvalidTimestampUnder.into_response();
        }

        utc_datetime
    } else {
        info!(target: "old_gen_events", "User ({}): Date received is in an invalid format.", claims.email);
        return ApiError::InvalidTimestampFormat.into_response();
    };

    let key = claims.generate_key_from_date(date.into(), false);

    info!(target: "encrypting_events", "User ({}): Whole key = {}", claims.email, key);

    let key = &BASE64_STANDARD
        .decode(&key)
        .expect("Couldnt decode base64 key");

    encrypt_aux(claims, file, cipher_bytes, hmac_bytes, filename, key).await
}

async fn decrypt_aux(claims: Claims, file: Vec<u8>, key: &[u8]) -> Response {
    let mut zip =
        zip::read::ZipArchive::new(Cursor::new(file.clone())).expect("Expected a zip file");
    assert_eq!(4, zip.len());
    let mut htbl = HashMap::new();
    let mut vec_files = Vec::new();
    for i in 0..zip.len() {
        let mut option = zip.by_index(i).expect("A file, lol");
        let mut options_buf = vec![0; option.size() as usize];
        option.read(&mut options_buf).expect("");
        if option.name() != "see-u-l4ter.options" || option.name() != "see-u-l4ter.hmac" {
            vec_files.push(option.name().to_owned());
        }
        htbl.insert(option.name().to_owned(), options_buf);
    }

    info!(target: "decrypting_events", "User ({}): Starting HMAC checks. HMAC Key used = {}", claims.email, BASE64_STANDARD.encode(&key[16..32]));

    let op = match htbl.get("see-u-l4ter.options") {
        Some(op) => op,
        None => {
            info!(target: "decrypting_events", "User ({}): Option file was not present. Sending error.", claims.email);
            return ApiError::InvalidFile("see-u-l4ter.options".into()).into_response();
        }
    };
    let op_hmac = match htbl.get("see-u-l4ter.hmac") {
        Some(op_h) => op_h,
        None => {
            info!(target: "decrypting_events", "User ({}): Option HMAC file was not present. Sending error.", claims.email);
            return ApiError::InvalidFile("see-u-l4ter.hmac".into()).into_response();
        }
    };

    match HashAlgorithms::HmacSha256.verify(&key[16..32], &op, &op_hmac) {
        Ok(_) => (),
        Err(_) => {
            info!(target: "decrypting_events", "User ({}): Option HMAC was invalid. Sending error.", claims.email);
            return ApiError::InvalidHmacOptions.into_response();
        }
    };

    let options = String::from_utf8(op.to_vec()).unwrap();

    info!(target: "decrypting_events", "User ({}): options read = {}", claims.email, options);

    let mut cipher_n = None;
    let mut hmac_n = None;

    for line in options.lines() {
        let parts: Vec<&str> = line.split('=').map(|s| s.trim()).collect();
        match parts.get(0) {
            Some(&"cipher") => {
                if let Ok(num) = parts.get(1).unwrap().parse::<i32>() {
                    cipher_n = Some(num);
                }
            }
            Some(&"hmac") => {
                if let Ok(num) = parts.get(1).unwrap().parse::<i32>() {
                    hmac_n = Some(num);
                }
            }
            _ => {}
        }
    }
    let cipher = match cipher_n {
        Some(1) => Cipher::aes_128_cbc(),
        Some(2) => Cipher::aes_128_ctr(),
        _ => {
            println!("{:?}, {:?}", cipher_n, hmac_n);
            panic!()
        }
    };

    let hmac = match hmac_n {
        Some(1) => HashAlgorithms::HmacSha256, //HmacSha256
        Some(2) => HashAlgorithms::HmacSha512, //HmacSha512
        _ => {
            println!("{:?}, {:?}", cipher_n, hmac_n);
            panic!()
        }
    };

    let filename = vec_files[0]
        .trim_end_matches(".enc")
        .trim_end_matches(".hmac")
        .to_string();
    let file_buf = match htbl.get(&format!("{}.enc", filename)) {
        Some(f) => f,
        None => {
            info!(target: "decrypting_events", "User ({}): Ciphertext not present. Sending error.", claims.email);
            return ApiError::InvalidFile(format!("{}.enc", filename).into()).into_response();
        }
    };
    let hmac_buf = match htbl.get(&format!("{}.hmac", filename)) {
        Some(h) => h,
        None => {
            info!(target: "decrypting_events", "User ({}): Ciphertext HMAC not present. Sending error.", claims.email);
            return ApiError::InvalidFile(format!("{}.hmac", filename).into()).into_response();
        }
    };

    match hmac.verify(&key[16..32], &file_buf, &hmac_buf) {
        Ok(_) => (),
        Err(_) => {
            info!(target: "decrypting_events", "User ({}): Ciphertext HMAC was invalid. Sending error.", claims.email);
            return ApiError::InvalidHmacCipherText.into_response();
        }
    };

    info!(target: "decrypting_events", "User ({}): All HMACs are valid. Starting decryption.", claims.email);

    let plaintext = decrypt(cipher, &key[0..16], Some(IV), &file_buf).expect("Decrypting failed");
    info!(target: "decrypting_events", "User ({}): Decryption ended. Key used = {}", claims.email, BASE64_STANDARD.encode(&key[0..16]));

    let mut buf = [0; 100_000];
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf[..]));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    zip.start_file(filename.clone(), options)
        .expect("Couldnt create file inside zip");
    zip.write(plaintext.as_slice())
        .expect("Couldnt write to file inside zip");

    info!(target: "decrypting_events", "User ({}): Plaintext stored inside zip.", claims.email);

    zip.finish().expect("Couldnt finish zip");
    drop(zip);

    info!(target: "decrypting_events", "User ({}): Zip finished. Sending now.", claims.email);

    let headers = [
        (header::CONTENT_TYPE, "application/zip; charset=utf-8"),
        (
            header::CONTENT_DISPOSITION,
            &format!("attachment; filename=\"{}.zip\"", filename),
        ),
    ];
    (headers, buf).into_response()
}

async fn decrypt_now(mut claims: Claims, mut mp: Multipart) -> Response {
    info!(target: "decrypting_events", "User ({}): Requested an decryption.", claims.email);
    let mut form = HashMap::new();

    while let Some(field) = mp.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        let data = field.bytes().await.unwrap();

        form.insert(name.clone(), data.clone());
    }

    let file = form.clone().get("data").expect("No file (data)").to_vec();
    let key = match form.clone().get("email") {
        Some(e) => {
            let e = String::from_utf8(e.to_vec()).expect("Couldnt get email");
            claims.generate_key_from_now_and_email(&e, false)
        }
        None => claims.generate_key_from_now(false),
    };

    info!(target: "decrypting_events", "User ({}): Key thats gonna be used = {}.", claims.email, key);

    let k = &BASE64_STANDARD.decode(&key).expect("Couldnt decode key");
    decrypt_aux(claims, file, k).await
}

async fn gen(mut claims: Claims) -> Response {
    info!(target: "gen_events", "User ({}): Requested a key from now timestamp.", claims.email);

    let key = claims.generate_key_from_now(false);

    info!(target: "gen_events", "User ({}): Key generated. Sending...", claims.email);

    let body = Json(json!({
    "key" : key
    }));
    (StatusCode::OK, body).into_response()
}

async fn old_gen(mut claims: Claims, mut mp: Multipart) -> Response {
    info!(target: "old_gen_events", "User ({}): Requested a key from old timestamp.", claims.email);
    let mut form = HashMap::new();

    while let Some(field) = mp.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        let data = field.bytes().await.unwrap();

        form.insert(name.clone(), data.clone());
    }

    let dt = form
        .clone()
        .get("timestamp")
        .expect("No timestamp")
        .to_vec();
    let t = String::from_utf8(dt).expect("Invalid timestamp");
    println!("t: {}", t);

    let now = chrono::Local::now();
    let offset = now.offset();

    let date = if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(&t, FORMAT_STR) {
        let temp: chrono::DateTime<<chrono::FixedOffset as TimeZone>::Offset> =
            chrono::DateTime::from_naive_utc_and_offset(naive, *offset);
        if temp > now {
            info!(target: "old_gen_events", "User ({}): Date received is in after now timestamp.", claims.email);
            return ApiError::InvalidTimestampOver.into_response();
        }

        temp
    } else {
        info!(target: "old_gen_events", "User ({}): Date received is in an invalid format.", claims.email);
        return ApiError::InvalidTimestampFormat.into_response();
    };

    let key = match form.clone().get("email") {
        Some(e) => {
            let e = String::from_utf8(e.to_vec()).expect("Couldnt get email");
            info!(target: "old_gen_events", "User ({}): User requested key for email = {}", claims.email, e);
            claims.generate_key_from_date_and_email(&e, date.into(), false)
        }
        None => {
            info!(target: "old_gen_events", "User ({}): User requested key for his own email", claims.email);
            claims.generate_key_from_date(date.into(), false)
        }
    };

    info!(target: "old_gen_events", "User ({}): Date received is in valid format. Key generated. Sending...", claims.email);

    let body = Json(json!({
    "key" : key
    }));
    (StatusCode::OK, body).into_response()
}

async fn login(
    Extension(pool): Extension<SqlitePool>,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials

    info!(target: "login_events", "User with email ({}) asked to sign in", payload.email);
    if payload.email.is_empty() || payload.client_secret.is_empty() {
        warn!(target: "login_events", "User with email ({}) had missing credentials. Aborting.", payload.email);
        return Err(AuthError::MissingCredentials);
    }

    let user = sqlx::query("SELECT * FROM users WHERE ? = email")
        .bind(payload.email.clone())
        .fetch_one(&pool)
        .await;

    let user = match user {
        Ok(u) => u,
        Err(_) => {
            warn!(target: "login_events", "User with email ({}) not found on the database. Aborting.", payload.email);
            return Err(AuthError::WrongCredentials);
        }
    };

    let p: String = user.get("password");
    let p_hash = PasswordHash::new(p.as_ref()).expect("AA");
    if Argon2::default()
        .verify_password(&payload.client_secret.into_bytes(), &p_hash)
        .is_err()
    {
        warn!(target: "login_events", "User with email ({}) inputed an incorrect password. Aborting.", payload.email);
        return Err(AuthError::WrongCredentials);
    }

    info!(target: "login_events", "User with email ({}) found on the database and their password is correct.", payload.email);

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

    claims.generate_key_from_now(true);

    // Create the authorization token
    let token = encode(&OtherHeader::default(), &claims, &KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    info!(target: "login_events", "Claims and Access Token for user with email ({}) have been generated. Sending now.", payload.email);

    // Send the authorized token
    Ok(Json(AuthBody::new(token)))
}

async fn register(
    Extension(pool): Extension<SqlitePool>,
    Json(payload): Json<RegisterPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    info!(target: "register_events", "User with email ({}) asked to register", payload.email);
    // Check if the user sent the credentials
    if payload.email.is_empty() || payload.client_secret.is_empty() {
        warn!(target: "login_events", "User with email ({}) had missing credentials. Aborting.", payload.email);
        return Err(AuthError::MissingCredentials);
    }

    let mut conn = pool.acquire().await.expect("oopsies");
    match sqlx::query("SELECT * FROM users WHERE ? = email")
        .bind(payload.email.clone())
        .fetch_one(&pool)
        .await
    {
        Ok(_) => {
            warn!(target: "register_events", "Another user with email ({}) found on the database. Duplicate Account. Aborting.", payload.email);
            return Err(AuthError::DuplicateAccount);
        }
        Err(_) => {}
    };

    info!(target: "register_events", "Registering user with email ({}): duplicate user not found on the database. Good to go.", payload.email);

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
        email: payload.email.clone(),
        key: String::new(),
        key_timestamp: now + (60 * 5),
        exp: now as usize + (60 * 5), // 5 mins
    };

    claims.generate_key_from_now(true);

    // Create the authorization token
    let token = encode(&OtherHeader::default(), &claims, &KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    info!(target: "register_events", "Registering user with email ({}) complete. Database updated, claims and token generated. Sending now.", payload.email);

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
