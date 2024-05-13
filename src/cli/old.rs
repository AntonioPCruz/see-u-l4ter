use crate::common::{error_out, read_from_config_file, ErrorBody, KeyBody, FORMAT_STR, str_of_date};

use clap::{parser::ValueSource, ArgMatches};
use chrono::{NaiveDateTime, TimeZone};

use reqwest::Client;

pub async fn old(xdg_dirs: xdg::BaseDirectories, sub_matches: &ArgMatches) {
    let t = sub_matches.get_one::<String>("timestamp").unwrap();
    let e = match sub_matches.get_one::<String>("email") {
        Some(e) => Some(e),
        None => None
    };

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Could not create Client");

    let timestamp_part = match sub_matches.value_source("timestamp") {
        Some(ValueSource::DefaultValue) => {
            reqwest::multipart::Part::text(t.to_string())
        }
        Some(ValueSource::CommandLine) => {
            let dt = chrono::Local::now();
            let offset = dt.offset();

            if let Ok(naive) = NaiveDateTime::parse_from_str(t, FORMAT_STR) {
                let t: chrono::DateTime<<chrono::FixedOffset as TimeZone>::Offset> =
                    chrono::DateTime::from_naive_utc_and_offset(naive, *offset);
                if t > dt {
                    error_out("The date can't be more than the time right now!")
                }

                reqwest::multipart::Part::text(str_of_date(t.into()))
            } else {
                error_out(
                    "The date string is not in the correct format! Try YEAR-MONTH-DAY-HOUR:MIN",
                );
                unreachable!()
            }
        }
        _ => unreachable!(),
    };

    let part = match e {
        Some(e) => reqwest::multipart::Form::new()
                    .part("timestamp", timestamp_part)
                    .part("email", reqwest::multipart::Part::text(e.to_string())),
        None => reqwest::multipart::Form::new()
                    .part("timestamp", timestamp_part)
    };

    println!("{:?}", e);

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
