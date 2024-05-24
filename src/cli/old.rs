use crate::common::*;

use clap::{parser::ValueSource, ArgMatches};
use chrono::{NaiveDateTime, TimeZone};

use reqwest::Client;

pub async fn old(xdg_dirs: xdg::BaseDirectories, sub_matches: &ArgMatches) {
    let t = sub_matches.get_one::<String>("timestamp").unwrap();
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Could not create Client");

    let timestamp_part = match sub_matches.value_source("timestamp") {
        Some(ValueSource::DefaultValue) => {
            reqwest::multipart::Part::text(t.to_string())
        }
        Some(ValueSource::CommandLine) => {
            let d = str_to_utc_string(t.to_string(), false);
            reqwest::multipart::Part::text(d)
        }
        _ => unreachable!(),
    };

    let part = reqwest::multipart::Form::new().part("timestamp", timestamp_part);

    let token = format!(
        "Bearer {}",
        read_from_config_file(xdg_dirs.clone(), "token".into())
    );

    let response = client
        .post("https://localhost:3000/api/old/gen")
        .header("Authorization", token)
        .multipart(part)
        .send()
        .await
        .expect("Error sending request");

    // Check the response status
    if response.status().is_success() {
        let key = response
            .json::<KeyBody>()
            .await
            .expect("Couldnt decode json");
        println!("Key: {}", key.key);
    } else {
        match response.json::<ErrorBody>().await {
            Ok(json_err) => error_out(&json_err.error),
            _ => error_out("Something went wrong."),
        }
    }
}
