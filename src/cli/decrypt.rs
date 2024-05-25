use rsa::pkcs1::{LineEnding, DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::sha2::{Digest, Sha256};

use crate::common::*;

use clap::ArgMatches;
use reqwest::Client;
use std::{
    fs::{self, File},
    io::Write,
};

pub async fn decrypt(xdg_dirs: xdg::BaseDirectories, sub_matches: &ArgMatches) {
    let f = sub_matches.get_one::<String>("FILE_NAME").unwrap().clone();
    let email_part = match sub_matches.get_one::<String>("email") {
        Some(e) => Some (reqwest::multipart::Part::text(format!("{}", e))),
        None => None
    };

    // By this point everything is in its correct form, a string. Lets transform them into
    // something we can send through a http form (multipart::Part)

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

    // And the actual form
    let part = match email_part {
        Some(e_p) => reqwest::multipart::Form::new()
            .part("data", file_part)
            .part("sig", sig_part)
            .part("email", e_p),
        None => reqwest::multipart::Form::new()
            .part("data", file_part)
            .part("sig", sig_part),
    };

    let token = format!("Bearer {}", read_from_config_file(xdg_dirs, "token".into()));

    // The response 
    let response = client
        .post("https://localhost:3000/api/now/decrypt")
        .header("Authorization", token)
        .multipart(part)
        .send()
        .await
        .expect("error on reqwest");

    // If the response is fine we create the zip and save whatever we get back from the response
    // into it. Otherwise something went wrong
    if response.status().is_success() {
        let zip_filename = format!("{}.decoded.zip", f.trim_end_matches(".zip"));

        let mut zip = File::create(zip_filename.clone()).expect("Couldn't create file");
        zip.write_all(&response.bytes().await.expect("Couldn't get bytes"))
            .unwrap_or_else(|_| {
                error_out("Response couldn't be parsed into zip");
                unreachable!()
            });
        success(
            format!(
                "{} received. Inside is your decrypted file!",
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
