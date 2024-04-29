use crate::common::success;
use crate::common::{error_out, ErrorBody, EMAIL_REGEX_PATTERN};
use inquire::{Password, Text};
use regex::Regex;
use reqwest::Client;
use serde_json::json;

use crate::common::write_to_config_file;
use crate::common::AuthBody;

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

    let request_body = json!({
        "name" : name,
        "email": email,
        "client_secret": password
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

        write_to_config_file(xdg_dirs, "token".into(), response.access_token);
        success("Registered and logged in! You have 5 minutes of inactivity time available, each request adds a minute!");
    } else {
        let response = response
            .json::<ErrorBody>()
            .await
            .expect("Couldnt decode json");
        error_out(&response.error);
    }
}