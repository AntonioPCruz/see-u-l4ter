use rsa::pkcs1::{LineEnding, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::sha2::{Digest, Sha256};
use crate::common::success;
use crate::common::{error_out, ErrorBody, EMAIL_REGEX_PATTERN};
use inquire::{Password, Text};
use regex::Regex;
use reqwest::Client;
use serde_json::json;

use crate::common::*;

pub async fn register(xdg_dirs: xdg::BaseDirectories) {
    println!("Welcome to see-u-l4ter!");
    let email = loop {
        let email = Text::new("Email:").prompt().expect("Error getting email");
        let email_regex = Regex::new(EMAIL_REGEX_PATTERN).unwrap();
        if email_regex.is_match(&email) {
            break email;
        } else {
            println!("Invalid email address, please try again.");
        }
    };
    let name = Text::new("Username:")
        .prompt()
        .expect("Error getting username");
    let password = Password::new("Password:")
        .prompt()
        .expect("Error getting pasword");

    let mut rng = rand::thread_rng();

    println!("Creating public and private RSA keys... (this might take a bit)");

    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let verifying_key = signing_key.verifying_key();

    let pk = private_key.to_public_key().to_pkcs1_pem(LineEnding::default()).expect("Couldnt create pk");

    let request_body = json!({
        "name" : name,
        "email": email,
        "client_secret" : password,
        "pk" : pk
    });

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Could not create Client");

    let response = client
        .post("https://localhost:3000/register")
        .json(&request_body)
        .send()
        .await
        .expect("Couldnt get request");

    if response.status().is_success() {
        let response = response
            .json::<AuthBody>()
            .await
            .expect("Couldnt decode json");

        let sk = private_key.to_pkcs1_pem(LineEnding::default()).expect("Coudlnt create pem for sk").to_string();
        write_to_config_file(xdg_dirs.clone(), "token".into(), response.access_token);
        write_config_file(xdg_dirs, "sk.pem".into(), sk);
        success("Registered and logged in! You have 5 minutes of inactivity time available, each request adds a minute!");
    } else {
        let response = response
            .json::<ErrorBody>()
            .await
            .expect("Couldnt decode json");
        error_out(&response.error);
    }
}
