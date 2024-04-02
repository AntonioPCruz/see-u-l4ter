use std::error::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::select;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = "127.0.0.1:8080";
    let mut stream = TcpStream::connect(addr).await?;
    let (reader, mut writer) = stream.split();
    let mut socket_lines = BufReader::new(reader).lines();
    let mut stdin_lines = BufReader::new(tokio::io::stdin()).lines();
    println!("Connected to server.");
    loop {
        select!(
            result = socket_lines.next_line() => {
                let Some(line) = result? else { break };
                println!("Response: {line}");
            },
            result = stdin_lines.next_line() => {
                let Some(email) = result? else { break };
                let password = stdin_lines.next_line();
                let Some(password) = password.await? else {break};
                writer.write_all(email.as_bytes()).await?;
                writer.flush().await?;

                writer.write_all(password.as_bytes()).await?;
                writer.flush().await?;
            },
        )
    }
    Ok(())
}
