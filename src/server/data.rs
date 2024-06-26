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
use log::info;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt::Display;

use crate::KEYS;

// general functions
pub fn str_of_date(d: chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "{}:{:02}:{:02}:{:02}:{:02}",
        d.year(),
        d.month(),
        d.day(),
        d.hour(),
        d.minute()
    )
}

fn clamp_to_5_minutes(dt: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    let minutes = dt.minute();
    let clamped_minutes = (minutes / 5) * 5; // Round down to the nearest 5-minute interval
    dt.with_minute(clamped_minutes).unwrap_or_else(|| dt)
}

pub fn ciphercode_to_string(c: u8) -> String {
    match c {
        1 => "AES-128-CBC".into(),
        2 => "AES-128-CTR".into(),
        _ => unreachable!(),
    }
}

pub fn hmaccode_to_string(h: u8) -> String {
    match h {
        1 => "HMAC-SHA256".into(),
        2 => "HMAC-SHA512".into(),
        _ => unreachable!(),
    }
}

// structs

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub email: String,
    pub key: String,
    pub key_timestamp: u64,
    pub exp: usize,
}

#[derive(Debug, Serialize)]
pub struct Profile {
    pub name: String,
    pub email: String,
}

pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
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
    pub pk: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterPayload {
    pub name: String,
    pub email: String,
    pub client_secret: String,
    pub pk: String,
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
    InvalidFile(String),
    InvalidSignature,
    InvalidHmacOptions,
    InvalidHmacCipherText,
    InvalidTimestampFormat,
    InvalidTimestampOver,
    InvalidTimestampUnder,
}

// impls

impl Claims {
    fn get_key(&mut self, email: &str, date: String, sub: bool) -> String {
        let scrt = {
            let mut tmp = email.to_string().trim().to_string();
            tmp.push_str("tenho 4 bananas no frigorifico");
            tmp.push_str(&date);
            tmp
        };
        let mut hasher = Sha256::new();
        hasher.update(scrt);

        // read hash digest and consume hasher
        let key = BASE64_STANDARD.encode(hasher.finalize());

        info!(target: "key_generation", "Email ({}): Date = {}, Generated key = {}", email, date, key);
        if sub {
            self.key = key.clone();
        }
        key
    }

    pub fn generate_key_from_now(&mut self, sub: bool) -> String {
        let now = chrono::Utc::now();
        println!("{}", now);
        let clamped_now = clamp_to_5_minutes(now);
        let res = str_of_date(clamped_now);
        let email = self.email.clone();
        self.get_key(&email, res, sub)
    }

    pub fn generate_key_from_now_and_email(&mut self, email: &str, sub: bool) -> String {
        let now = chrono::Utc::now().into();
        let clamped_now = clamp_to_5_minutes(now);
        let res = str_of_date(clamped_now);
        self.get_key(&email, res, sub)
    }

    pub fn generate_key_from_date(
        &mut self,
        date: chrono::DateTime<chrono::Utc>,
        sub: bool,
    ) -> String {
        let clamped_now = clamp_to_5_minutes(date);
        let res = str_of_date(clamped_now);
        let email = self.email.clone();
        self.get_key(&email, res, sub)
    }

    pub fn generate_key_from_date_and_email(
        &mut self,
        email: &str,
        date: chrono::DateTime<chrono::Utc>,
        sub: bool,
    ) -> String {
        let clamped_now = clamp_to_5_minutes(date);
        let res = str_of_date(clamped_now);
        self.get_key(&email, res, sub)
    }
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

impl Keys {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
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
                "Invalid token, please, log back in or register.",
            ),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::InvalidFile(s) => {
                let msg = format!("Invalid file. {} not present.", s);
                (StatusCode::BAD_REQUEST, msg)
            }
            ApiError::InvalidSignature => (
                StatusCode::BAD_REQUEST,
                "Careful! The signature doesn't match! Did someone change the file mid-way?".to_string(),
            ),
            ApiError::InvalidHmacOptions => (
                StatusCode::BAD_REQUEST,
                "Careful! The HMAC for the options doesn't match! Did the file get modified or should you wait a little bit more?".to_string(),
            ),
            ApiError::InvalidHmacCipherText => (
                StatusCode::BAD_REQUEST,
                "Careful! The HMAC for the encoded file doesn't match!".to_string(),
            ),
            ApiError::InvalidTimestampFormat => (
                StatusCode::BAD_REQUEST,
                "The date string is not in the correct format! Try YEAR-MONTH-DAY-HOUR:MIN"
                    .to_string(),
            ),
            ApiError::InvalidTimestampOver => (
                StatusCode::BAD_REQUEST,
                "The date can't be after the current date!".to_string(),
            ),
            ApiError::InvalidTimestampUnder => (
                StatusCode::BAD_REQUEST,
                "The date can't be before the current date!".to_string(),
            ),
        };
        let body = Json(json!({
            "error": &error_message,
        }));
        (status, body).into_response()
    }
}

// unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn test_clamp_to_5_minutes() {
        // Test a time where minutes are not at a multiple of 5
        let dt1 = chrono::Utc
            .with_ymd_and_hms(2024, 12, 3, 14, 37, 0)
            .unwrap();
        assert_eq!(
            clamp_to_5_minutes(dt1),
            chrono::Utc
                .with_ymd_and_hms(2024, 12, 3, 14, 35, 0)
                .unwrap()
        );

        // Test a time where minutes are at a multiple of 5
        let dt2 = chrono::Utc
            .with_ymd_and_hms(2024, 12, 3, 14, 30, 0)
            .unwrap();
        assert_eq!(
            clamp_to_5_minutes(dt2),
            chrono::Utc
                .with_ymd_and_hms(2024, 12, 3, 14, 30, 0)
                .unwrap()
        );

        // Test a time where minutes are exactly at 0
        let dt3 = chrono::Utc
            .with_ymd_and_hms(2024, 12, 3, 17, 45, 0)
            .unwrap();
        assert_eq!(
            clamp_to_5_minutes(dt3),
            chrono::Utc
                .with_ymd_and_hms(2024, 12, 3, 17, 45, 0)
                .unwrap()
        );

        // Test a time where minutes are exactly at 55
        let dt4 = chrono::Utc
            .with_ymd_and_hms(2024, 12, 3, 17, 55, 0)
            .unwrap();
        assert_eq!(
            clamp_to_5_minutes(dt4),
            chrono::Utc
                .with_ymd_and_hms(2024, 12, 3, 17, 55, 0)
                .unwrap()
        );

        // Test a time where minutes are at 59
        let dt5 = chrono::Utc
            .with_ymd_and_hms(2024, 12, 3, 17, 59, 0)
            .unwrap();
        assert_eq!(
            clamp_to_5_minutes(dt5),
            chrono::Utc
                .with_ymd_and_hms(2024, 12, 3, 17, 55, 0)
                .unwrap()
        );

        // Test a time where minutes are at 1
        let dt5 = chrono::Utc.with_ymd_and_hms(2024, 12, 3, 17, 1, 0).unwrap();
        assert_eq!(
            clamp_to_5_minutes(dt5),
            chrono::Utc.with_ymd_and_hms(2024, 12, 3, 17, 0, 0).unwrap()
        );
    }
}
