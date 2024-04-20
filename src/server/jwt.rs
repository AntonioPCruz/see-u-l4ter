use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use axum_extra::{
    headers::{authorization::Bearer, Authorization, Header},
    TypedHeader,
};
use jsonwebtoken::{decode, encode, Header as OtherHeader, TokenData, Validation};

use crate::{AuthError, Claims, KEYS};

pub async fn refresh_middleware(
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let token_data = decode::<Claims>(auth.token(), &KEYS.decoding, &Validation::default())
        .map_err(|_| AuthError::InvalidToken)
        .expect("Couldnt decode token");

    let mut response = next.run(request).await;

    match token_is_valid(&token_data) {
        true => {
            let claims = Claims {
                sub: token_data.claims.sub,
                company: token_data.claims.company,
                exp: token_data.claims.exp + 60,
            };

            let token = encode(&OtherHeader::default(), &claims, &KEYS.encoding)
                .map_err(|_| AuthError::TokenCreation)
                .expect("Couldnt encode token");

            println!("{}", token);

            response.headers_mut().insert(
                Authorization::<Bearer>::name(),
                HeaderValue::from_str(&token).expect("Couldnt create header value"),
            );

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
