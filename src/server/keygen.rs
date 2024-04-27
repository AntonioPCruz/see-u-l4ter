use axum::{
    extract::Request,
    http::HeaderValue,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization, Header},
    TypedHeader,
};
use jsonwebtoken::{decode, encode, Header as OtherHeader, TokenData, Validation};

use crate::data::*;
use crate::KEYS;

pub async fn keygen_middleware(
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let token_data = decode::<Claims>(auth.token(), &KEYS.decoding, &Validation::default())
        .map_err(|_| AuthError::InvalidToken);

    let token_data = match token_data {
        Ok(token) => token,
        Err(e) => {
            println!("Error while decoding token. Sending error message");
            return Ok(e.into_response());
        }
    };

    let mut response = next.run(request).await;

    match key_is_valid(&token_data.claims.key_timestamp) {
        (_, true) => Ok(response),
        (now, false) => {
            let mut claims = Claims {
                email: token_data.claims.email,
                key: String::new(),
                key_timestamp: now + (60 * 5), // 5 minutes
                exp: token_data.claims.exp,
            };

            claims.generate_key_from_now("testing");

            println!("key = {}", claims.key);

            let token = encode(&OtherHeader::default(), &claims, &KEYS.encoding)
                .map_err(|_| AuthError::TokenCreation)
                .expect("Couldnt encode token");

            response.headers_mut().insert(
                Authorization::<Bearer>::name(),
                HeaderValue::from_str(&token).expect("Couldnt create header value"),
            );

            Ok(response)
        }
    }
}

fn key_is_valid(key_timestamp: &u64) -> (u64, bool) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    (now, now < *key_timestamp)
}
