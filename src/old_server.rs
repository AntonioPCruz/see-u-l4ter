use base64::prelude::*;
use chrono::{Datelike, Timelike};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
// use hmac::{Hmac, Mac};
use jsonwebtoken::{
    decode, encode, get_current_timestamp, Algorithm, DecodingKey, EncodingKey, Header, TokenData,
    Validation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use warp::{Filter, Rejection};

#[derive(Clone, Debug, Deserialize)]
struct User {
    uid: u32,
    email: String,
    encrypted_password: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Tokens {
    refresh_token: String,
    access_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    user_id: u32,
    email: String,
    exp: u64,
}

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

#[derive(Debug, Deserialize)]
struct Connection {
    current_key: String,
    user: User,
}

static NEXT_CON_ID: AtomicUsize = AtomicUsize::new(1);
type Connections = Arc<Mutex<HashMap<usize, Connection>>>;

impl Connection {
    pub fn new(user: User) -> Self {
        Connection {
            current_key: String::new(),
            user,
        }
    }

    fn get_key(&mut self, email: &str, password: &str, date: String) -> String {
        let scrt = {
            let mut tmp = email.to_string().trim().to_string();
            tmp.push_str("tenho 4 bananas no frigorifico");
            tmp.push_str(password.trim());
            tmp.push_str(&date);
            println!("{}", date);
            tmp
        };
        let mut hasher = Sha256::new();
        hasher.update(scrt);

        // read hash digest and consume hasher
        let key = BASE64_STANDARD.encode(hasher.finalize());
        self.current_key = key.clone();
        key
    }

    fn generate_key_from_now(&mut self, email: &str, password: &str) -> String {
        let now = chrono::offset::Local::now();
        let res = str_of_date(now);
        self.get_key(email, password, res)
    }

    fn generate_key_from_date(
        &mut self,
        email: &str,
        password: &str,
        date: chrono::DateTime<chrono::Local>,
    ) -> String {
        let res = str_of_date(date);
        self.get_key(email, password, res)
    }
}

pub async fn server() {
    // let connects: Connections = Arc::new(Mutex::new(HashMap::new()));
    // let connects = warp::any().map(move || connects.clone());
    let secret_key = warp::any().map(move || "my_very_secret_wow_i_love_you_yilongma".to_string());

    let login = warp::path!("login")
        .and(warp::post())
        .and(warp::body::json())
        .and(secret_key)
        .and_then(login);

    let refresh_token = warp::path!("refresh_token")
        .and(warp::post())
        .and(warp::body::json())
        .and(secret_key)
        .and_then(refresh_token);
    let auth_route = warp::path!("teste").and(auth(secret_key)).and_then(teste_route);

    let hello = login.or(refresh_token).or(auth_route);

    warp::serve(hello).run(([127, 0, 0, 1], 8000)).await;
}

fn auth<F: Filter + Clone>(s: F) -> impl Filter<Extract = (User,), Error = Rejection> + Copy where <F as warp::filters::FilterBase>::Error: warp::reject::sealed::CombineRejection<Rejection> {
    warp::header::<String>("access_token").and(s).and_then(|_access_token, secret| async move {
        match decode::<Claims>(
            &("".to_string()),
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        ) {
            Ok(TokenData { claims, .. }) => Ok(User {
                email: claims.email,
                uid: claims.user_id,
                encrypted_password: "".to_string(),
            }),
            Err(_) => Err(warp::reject::reject()),
        }
    })
}

async fn teste_route(user: User) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::html("Helo"))
}

#[derive(Debug, Serialize)]
struct Response {
    msg: String,
}

async fn login(user: User, secret: String) -> Result<impl warp::Reply, warp::Rejection> {
    // Verify user
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("f")
        .as_secs();

    println!("O dia foi!");
    let claims_access = Claims {
        email: user.email.to_string(),
        exp: exp + 60,
        user_id: user.uid,
    };
    println!("E o claims tambem!");
    let access_token = encode(
        &Header::default(),
        &claims_access,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("Generating access token");
    println!("Vamos embora!");
    let claims_refresh = Claims {
        email: user.email.to_string(),
        exp: exp + (60 * 60 * 24 * 15),
        user_id: user.uid,
    };
    let refresh_token = encode(
        &Header::default(),
        &claims_refresh,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("Generating access token");
    println!("Esta quase!");
    let r = serde_json::to_string(&Tokens {
        access_token,
        refresh_token,
    })
    .expect("r");
    Ok(warp::reply::json(&(Response { msg: r })))
}

async fn refresh_token(
    tokens: Tokens,
    secret: String,
) -> Result<impl warp::Reply, warp::Rejection> {
    let claims = match decode::<Claims>(
        &tokens.refresh_token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    ) {
        Ok(e) => e.claims,
        Err(_) => return Err(warp::reject::reject()),
    };

    let exp = get_current_timestamp();
    let claims = Claims {
        email: claims.email.to_string(),
        exp: exp + 60,
        user_id: claims.user_id,
    };
    let access = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("Generating access token");

    Ok(warp::reply::json(&(Response { msg: access })))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn get_key_test() {
        let mut con = Connection::new(User {
            uid: 1,
            email: "testing".to_string(),
            encrypted_password: "test".to_string(),
        });

        let date = "1989:06:04:00:00";
        let email = con.user.email.clone();
        let pass = con.user.encrypted_password.clone();
        con.get_key(&email, &pass, date.to_string());
        assert_eq!(
            con.current_key,
            "LdfMAYTPMb3Vh2fBvQ7FPxN3qBktsLu0GvaDo3VE/Bw="
        );
    }
}
