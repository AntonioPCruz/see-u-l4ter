use clap::{Command, arg};
mod server;
mod client;

fn cli() -> Command {
  Command::new("see-u-la4ter")
    .about("A fictional versioning CLI")
    .subcommand_required(true)
    .subcommand(
      Command::new("encrypt")
      .about("Encrypt stuff")
      .arg(arg!(<FILE_NAME> "Some argument"))
      .arg_required_else_help(true),
    )
    .subcommand(
        Command::new("decrypt")
        .about("Decrypt the stuff you encrypted, lol")
    )
    .subcommand(
        Command::new("server")
        .about("Run the API web server")
    )
    .subcommand(
        Command::new("Client")
        .about("Run some client, not sure yet!")
    )
}

#[tokio::main]
async fn main() {
    let cmd = cli().get_matches();
    match cmd.subcommand() {
        Some(("encrypt", sub_matches)) => {
            let f = sub_matches.get_one::<String>("FILE_NAME").unwrap();
            print!("Hello encrypt command and arg: {}", f);
        },
        Some(("decrypt", _sub_matches)) => {
            print!("Hello from decrypt command! :)");
        },
        Some(("server", _sub_matches)) => {
            server::server().await;
        },
        Some(("client", _sub_matches)) => {
            client::client().await.unwrap();
        },
        _ => unreachable!(),
    }
}
