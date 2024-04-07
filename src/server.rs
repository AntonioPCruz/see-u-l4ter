use base64::prelude::*;
use chrono::{Datelike, Timelike};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
// use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use warp::Filter;

#[derive(Clone, Debug, Deserialize)]
struct User {
    uid: u32,
    email: String,
    encrypted_password: String,
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
    let connects: Connections = Arc::new(Mutex::new(HashMap::new()));
    let connects = warp::any().map(move || connects.clone());

    let login = warp::path!("login")
        .and(warp::post())
        .and(warp::body::json())
        .and(connects)
        .and_then(user_connected);

    let hello = login;

    warp::serve(hello).run(([127, 0, 0, 1], 8000)).await;
}

#[derive(Debug, Serialize)]
struct Response {
    msg: String,
}

async fn user_connected(
    user: User,
    connects: Connections,
) -> Result<impl warp::Reply, warp::Rejection> {
    let con_id = NEXT_CON_ID.fetch_add(1, Ordering::Relaxed);
    eprintln!("new user, id = {}, connection id = {}", user.uid, con_id);

    let mut con = Connection::new(user.clone());
    con.generate_key_from_now(&user.email, &user.encrypted_password);

    let k = con.current_key.clone();

    connects.lock().unwrap().insert(con_id, con);

    println!("connections = {:?}", connects);

    Ok(warp::reply::json(&(Response { msg: k })))
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
