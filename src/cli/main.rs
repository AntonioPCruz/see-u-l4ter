mod common;
use clap::{arg, builder::OsStr, Arg, Command};
use encrypt::encrypt;
use login::login;
mod encrypt;
mod login;

fn cli() -> Command {
    let encrypt = Command::new("encrypt")
        .short_flag('e')
        .about("Encrypt something")
        .arg(arg!(<FILE_NAME> "The file you wish to encrypt"))
        .arg(
            Arg::new("cipher")
                .short('c')
                .help("Optional Integer: 1 -> AES-128-CBC, 2 -> AES-128-CTR.")
                .required(false)
                .default_value(OsStr::from("1")),
        )
        .arg(
            Arg::new("hmac")
                .short('m')
                .help("Optional Integer: 1 -> HMAC-SHA256, 2 -> HMAC-SHA512.")
                .required(false)
                .default_value(OsStr::from("1")),
        )
        .arg(
            Arg::new("timestamp")
                .short('t')
                .help("Optional Time   : YEAR-MONTH-DAY-HOUR:MIN. Default: Current Time")
                .required(false)
                .default_value(OsStr::from(common::str_of_date(chrono::Local::now()))),
        )
        .arg_required_else_help(true);

    let decrypt = Command::new("decrypt")
        .short_flag('d')
        .about("Decrypt something")
        .arg(arg!(<FILE_NAME> "The file you wish to decrypt"))
        .arg(Arg::new("key")
            .help("Optional: SHA256/512 key. If this is not provided, the system will try to decrypt the file with a key generated with the current time.")
            .required(false)
            .default_value(OsStr::from(common::str_of_date(chrono::Local::now())))
        )
        .arg_required_else_help(true);

    Command::new("see-u-l4ter")
        .about("")
        .subcommand_required(true)
        .subcommand(encrypt)
        .subcommand(decrypt)
        .subcommand(Command::new("watch").about("Accompany the key changes every 5 minutes."))
        .subcommand(Command::new("login").about("Log into the server."))
        .subcommand(Command::new("register").about("Register an account."))
        .subcommand(Command::new("gen").about("Generate a key for a given timestamp"))
        .subcommand(Command::new("config").about("Configure your email and password"))
}

#[tokio::main]
async fn main() {
    let xdg_dirs =
        xdg::BaseDirectories::with_prefix("see-u-l4ter").expect("Coudln't get xdg folder");
    let cmd = cli().get_matches();
    match cmd.subcommand() {
        Some(("encrypt", sub_matches)) => encrypt(xdg_dirs, sub_matches).await,
        Some(("decrypt", _sub_matches)) => {
            println!("Hello from decrypt command! :)");
        }

        Some(("login", _)) => login(xdg_dirs).await,
        _ => unreachable!(),
    }
}
