use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json, RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use base64::prelude::*;
use chrono::{Datelike, Timelike};
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt::Display;

use crate::KEYS;

pub fn str_of_date(d: chrono::DateTime<chrono::Local>) -> String {
    format!(
        "{}:{:02}:{:02}:{:02}:{:02}",
        d.year(),
        d.month(),
        d.day(),
        d.hour(),
        d.minute()
    )
}

impl Display for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let t_exp =
            chrono::DateTime::from_timestamp(self.exp as i64, 0).expect("Couldnt create timestamp");
        let t_exp = t_exp.format("%Y-%m-%d %H:%M:%S");

        let k_exp = chrono::DateTime::from_timestamp(self.key_timestamp as i64, 0)
            .expect("Couldnt create timestamp");
        let k_exp = k_exp.format("%Y-%m-%d %H:%M:%S");

        write!(
            f,
            "Email: {}\nCurrent Key: {}\nKey Expiry: {}\nToken Expiry: {}",
            self.email, self.key, k_exp, t_exp
        )
    }
}

impl AuthBody {
    pub fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let token_data = decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials."),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials."),
            AuthError::DuplicateAccount => (
                StatusCode::BAD_REQUEST,
                "Email already in use, kindly choose another email.",
            ),
            AuthError::TokenCreation => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error.")
            }
            AuthError::InvalidToken => (
                StatusCode::BAD_REQUEST,
                "Invalid token, please, log back in.",
            ),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl Keys {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub email: String,
    pub key: String,
    pub key_timestamp: u64,
    pub exp: usize,
}

impl Claims {
    fn get_key(&mut self, email: &str, password: &str, date: String) -> String {
        let scrt = {
            let mut tmp = email.to_string().trim().to_string();
            tmp.push_str("tenho 4 bananas no frigorifico");
            tmp.push_str(password.trim());
            tmp.push_str(&date);
            tmp
        };
        let mut hasher = Sha256::new();
        hasher.update(scrt);

        // read hash digest and consume hasher
        let key = BASE64_STANDARD.encode(hasher.finalize());
        self.key = key.clone();
        key
    }

    pub fn generate_key_from_now(&mut self, password: &str) -> String {
        let now = chrono::offset::Local::now();
        let res = str_of_date(now);
        let email = self.email.clone();
        self.get_key(&email, password, res)
    }

    pub fn generate_key_from_date(
        &mut self,
        password: &str,
        date: chrono::DateTime<chrono::Local>,
    ) -> String {
        let res = str_of_date(date);
        let email = self.email.clone();
        self.get_key(&email, password, res)
    }
}

#[derive(Debug, Serialize)]
pub struct AuthBody {
    pub access_token: String,
    pub token_type: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthPayload {
    pub email: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterPayload {
    pub name: String,
    pub email: String,
    pub client_secret: String,
}

#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    DuplicateAccount,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
}

#[derive(Debug)]
pub enum ApiError {
    InvalidFile,
}
