use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use axum_extra::{
    headers::{authorization::Bearer, Authorization, Header},
    TypedHeader,
};
use jsonwebtoken::{decode, encode, Header as OtherHeader, TokenData, Validation};
use log::{info, warn};

use crate::{AuthError, Claims, KEYS};

pub async fn refresh_middleware(
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let token_data = decode::<Claims>(auth.token(), &KEYS.decoding, &Validation::default())
        .map_err(|_| AuthError::InvalidToken);

    let token_data = match token_data {
        Ok(token) => token,
        Err(e) => {
            warn!(target: "middleware_events", "Token received is invalid. Sending an error message.");
            return Err(e);
        }
    };

    let mut response = next.run(request).await;

    match token_is_valid(&token_data) {
        true => {
            info!(target: "middleware_events", "Generating new token for user ({}) for 1 more minute of activity.", token_data.claims.email);
            let claims = Claims {
                email: token_data.claims.email.clone(),
                key: token_data.claims.key,
                key_timestamp: token_data.claims.key_timestamp,
                exp: token_data.claims.exp + 60,
            };

            let token = encode(&OtherHeader::default(), &claims, &KEYS.encoding)
                .map_err(|_| AuthError::TokenCreation)
                .expect("Couldnt encode token");

            response.headers_mut().insert(
                Authorization::<Bearer>::name(),
                HeaderValue::from_str(&token).expect("Couldnt create header value"),
            );

            info!(target: "middleware_events", "New token for user ({}) generated. Sending now.", token_data.claims.email);

            Ok(response)
        }
        false => Err(AuthError::InvalidToken),
    }
}

fn token_is_valid(token: &TokenData<Claims>) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize;

    token.claims.exp > now
}
