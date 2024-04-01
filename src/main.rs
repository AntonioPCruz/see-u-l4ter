use base64::prelude::*;
use chrono::{Datelike, TimeZone, Timelike};
// use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::io::stdin;

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

// enum Server {
//     HasKey(Key),
//     MakingKey
// }
//
// enum Connection {
//     Encrypting(File),
//     Decrypting(File),
//     Waiting
// };

fn main() {
    let mut con = Connection::new();
    let (mut email, mut password) = (String::new(), String::new());
    stdin().read_line(&mut email).expect("oops");
    stdin().read_line(&mut password).expect("oops");

    let result = con.generate_key_from_now(&email, &password);
    println!("{:?}", result);

    let local_time = chrono::Local.with_ymd_and_hms(1989, 6, 4, 0, 0, 0).unwrap();
    let result = con.generate_key_from_user(&email, &password, local_time);
    println!("{:?}", result);
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
