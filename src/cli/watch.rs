use crate::common::{error_out, read_from_config_file, KeyBody, ErrorBody, FORMAT_STR};

use reqwest::Client;
use std::time::{Duration, Instant};

pub async fn watch(xdg_dirs: xdg::BaseDirectories, email: &str) {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Could not create Client");
    
    let mut interval = tokio::time::interval(Duration::from_secs(280)); // 5 minutes -1 second
    interval.tick().await;

    loop {
        let now = chrono::Local::now();
        let token = format!("Bearer {}", read_from_config_file(xdg_dirs.clone(), "token".into()));

        let response = client
            .post("https://localhost:3000/api/now/gen")
            .header("Authorization", token)
            .send()
            .await
            .expect("Error sending request");

        // Check the response status
        if response.status().is_success() {
            let key =
                response.json::<KeyBody>().await.expect("Couldnt decode json");
                println!("[{}] Key: {}", now.format(FORMAT_STR), key.key);
        } else {
            match response.json::<ErrorBody>().await {
                Ok(json_err) => error_out(&json_err.error),
                _ => error_out("Something went wrong."),
            }
        }

        interval.tick().await;
    }
}
