use rsa::pkcs1::{LineEnding, DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::sha2::{Digest, Sha256};

use crate::common::*;

use clap::{parser::ValueSource, ArgMatches};
use reqwest::Client;
use std::{
    fs::{self, File},
    io::Write,
};

pub async fn encrypt(xdg_dirs: xdg::BaseDirectories, sub_matches: &ArgMatches) {
    let mut is_now = false;
    let f = sub_matches.get_one::<String>("FILE_NAME").unwrap().clone();
    let t = sub_matches.get_one::<String>("timestamp").unwrap();
    let hmac = sub_matches
        .get_one::<String>("hmac")
        .unwrap()
        .parse::<u8>()
        .unwrap_or_else(|_| {
            error_out("Please provide an integer ([1; 2]) for the hmac!");
            unreachable!()
        });
    let c = sub_matches
        .get_one::<String>("cipher")
        .unwrap()
        .parse::<u8>()
        .unwrap_or_else(|_| {
            error_out("Please provide an integer ([1; 2]) for the cipher!");
            unreachable!()
        });

    if (hmac < 1 || hmac > 2) || (c < 1 || c > 2) {
        error_out("-hmac and -cipher need to be either 1 or 2!");
    }

    // By this point everything is in its correct form, a string. Lets transform them into
    // something we can send through a http form (multipart::Part)

    let timestamp_part = match sub_matches.value_source("timestamp") {
        Some(ValueSource::DefaultValue) => {
            is_now = true;
            let d = str_to_utc_string(t.to_string(), true);
            reqwest::multipart::Part::text(d)
        }
        Some(ValueSource::CommandLine) => {
            let d = str_to_utc_string(t.to_string(), true);
            reqwest::multipart::Part::text(d)
        }
        _ => unreachable!(),
    };

    // Lets also start the server and make it accept self-signed certs for our TLS
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Could not create Client");

    // And read the file we want to encrypt
    let file = fs::read(f.clone()).unwrap_or_else(|_| {
        error_out("File couldn't be read! Does it exist?");
        unreachable!()
    });

    // Sign the file with RSA private key
    let mut rng = rand::thread_rng();

    let sk_str = read_config_file(xdg_dirs.clone(), "sk.pem".into());
    let sk = rsa::RsaPrivateKey::from_pkcs1_pem(&sk_str).expect("Coudlnt get sk");

    let signing_key = SigningKey::<Sha256>::new(sk);
    let sig = signing_key.sign_with_rng(&mut rng, &file);

    // Lets create the form fields
    let file_part = reqwest::multipart::Part::bytes(file).file_name(f.clone());
    let sig_part = reqwest::multipart::Part::bytes(sig.to_vec()).file_name("sig");
    let cipher_part = reqwest::multipart::Part::text(format!("{}", c));
    let hmac_part = reqwest::multipart::Part::text(format!("{}", hmac));
    let filename_part = reqwest::multipart::Part::text(format!("{}", f.clone()));

    // And the actual form
    let part = reqwest::multipart::Form::new()
        .part("data", file_part)
        .part("sig", sig_part)
        .part("filename", filename_part)
        .part("cipher", cipher_part)
        .part("hmac", hmac_part)
        .part("timestamp", timestamp_part);

    let api_route = match is_now {
        true => "https://localhost:3000/api/now/encrypt",
        false => "https://localhost:3000/api/later/encrypt",
    };

    let token = format!("Bearer {}", read_from_config_file(xdg_dirs, "token".into()));

    // The response (the Authorization token should come from the config.ini probably)
    let response = client
        .post(api_route)
        .header("Authorization", token)
        .multipart(part)
        .send()
        .await
        .expect("error on reqwest");

    // If the response is fine we create the zip and save whatever we get back from the response
    // into it. Otherwise something went wrong
    if response.status().is_success() {
        let zip_filename = format!("{}.zip", f);

        let mut zip = File::create(zip_filename.clone()).expect("Couldn't create file");
        zip.write_all(&response.bytes().await.expect("Couldn't get bytes"))
            .unwrap_or_else(|_| {
                error_out("Response couldn't be parsed into zip");
                unreachable!()
            });
        success(
            format!(
                "{} received. Inside is your encrypted file and your HMAC!",
                zip_filename
            )
            .as_str(),
        );
    } else {
        match response.json::<ErrorBody>().await {
            Ok(json_err) => error_out(&json_err.error),
            _ => error_out("Something went wrong."),
        }
    }
}
