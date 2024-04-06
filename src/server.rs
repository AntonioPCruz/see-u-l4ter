use base64::prelude::*;
use chrono::{Datelike, Timelike};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
// use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use warp::Filter;

fn str_of_date(d: chrono::DateTime<chrono::Local>) -> String {
    format!(
        "{}:{:02}:{:02}:{:02}:{:02}",
        d.year(),
        d.month(),
        d.day(),
        d.hour(),
        d.minute()
    )
}

struct Connection {
    current_key: String,
}

impl Connection {
    pub fn new() -> Self {
        Connection {
            current_key: String::new(),
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

    fn generate_key_from_user(
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

    let hello = warp::path!("encrypt").map(|| {
        format!("Encrypt")
    })
    .or(warp::path!("decrypt").map(|| {format!("Decrypt")}))
    .or(warp::any().map(|| { format!("Any page (404)") }));

    warp::serve(hello)
        .run(([127, 0, 0, 1], 8000))
        .await;
    /* let listener = TcpListener::bind("127.0.0.1:8080").await?;
    loop {
        let (mut socket, _) = listener.accept().await?;

        let mut con = Connection::new();

        tokio::spawn(async move {
            let mut email = [0; 1024];
            let mut pass = [0; 1024];

            // In a loop, read data from the socket and write the data back.
            loop {
                match (socket.read(&mut email).await, socket.read(&mut pass).await) {
                    (Ok(_), Ok(_)) => {
                        let email =
                            String::from_utf8(email.to_vec()).expect("couldnt convert email");
                        let password =
                            String::from_utf8(pass.to_vec()).expect("couldnt convert pass");
                        let result = con.generate_key_from_now(&email, &password);
                        println!("{:?}", result);
                        socket.write_all(result.as_bytes()).await.expect("oops");
                    }
                    _ => panic!("not valid"),
                }
            }
        });
    } */
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn get_key_test() {
        let mut con = Connection::new();
        let email = "testing".to_string();
        let password = "test".to_string();

        let date = "1989:06:04:00:00";
        con.get_key(&email, &password, date.to_string());
        assert_eq!(
            con.current_key,
            "LdfMAYTPMb3Vh2fBvQ7FPxN3qBktsLu0GvaDo3VE/Bw="
        );
    }
}
