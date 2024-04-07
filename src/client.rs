use reqwest::Client;
use serde_json::json;

pub async fn client() -> Result<(), Box<dyn std::error::Error>> {
    let request_body = json!({
        "uid": 52,
        "email": "example@example.com",
        "encrypted_password": "password123"
    });

    let client = Client::new();

    let response = client
        .post("http://127.0.0.1:8000/login")
        .json(&request_body)
        .send()
        .await?;

    if response.status().is_success() {
        println!("Login success. Key = {}", response.text().await?);
    } else {
        println!("Login failed: {}", response.status());
    }

    Ok(())
}
