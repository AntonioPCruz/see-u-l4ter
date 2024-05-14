mod common;
use clap::{arg, builder::OsStr, Arg, Command};
use decrypt::decrypt;
use encrypt::encrypt;
use login::login;
use register::register;
mod encrypt;
mod decrypt;
mod old;
mod watch;
mod login;
mod register;

fn cli() -> Command {
    let encrypt = Command::new("encrypt")
        .short_flag('e')
        .about("Encrypt something.")
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
                .default_value(OsStr::from(common::str_of_date_local(chrono::Local::now()))),
        )
        .arg_required_else_help(true);

    // Try to decrypt something using the current 5 minute interval timestamp or an old one,
    // and an email provided by the user/user's email.
    let decrypt = Command::new("decrypt")
        .short_flag('d')
        .about("Decrypt something.")
        .arg(arg!(<FILE_NAME> "The file you wish to decrypt"))
        .arg(Arg::new("email")
            .short('e')
            .help("Optional String   : The email associated with the encrytion step. If this is not provided, your email will be used.")
            .required(false)
        )
        .arg_required_else_help(true);

    let old = Command::new("old")
        .short_flag('o')
        .about("Generate a key for a past timestamp.")
        .arg(
            Arg::new("timestamp")
                .short('t')
                .help("YEAR-MONTH-DAY-HOUR:MIN")
                .required(true)
                .default_value(OsStr::from(common::str_of_date_local(chrono::Local::now()))),
        )
        .arg(Arg::new("email")
            .short('e')
            .help("Optional String   : The email associated with the key. If this is not provided, your email will be used.")
            .required(false)
        )
        .arg_required_else_help(true);

    let watch = Command::new("watch")
        .short_flag('w')
        .about("Accompany the key changes every 5 minutes.")
        .arg(Arg::new("email")
            .short('e')
            .help("Optional String   : The email associated with the key. If this is not provided, your email will be used.")
            .required(false)
        );

    Command::new("see-u-l4ter")
        .about("")
        .subcommand_required(true)
        .subcommand(encrypt)
        .subcommand(decrypt)
        .subcommand(old)
        .subcommand(watch)
        .subcommand(Command::new("login").about("Log into the server."))
        .subcommand(Command::new("register").about("Register an account."))
}

#[tokio::main]
async fn main() {
    let xdg_dirs =
        xdg::BaseDirectories::with_prefix("see-u-l4ter").expect("Coudln't get xdg folder");
    let cmd = cli().get_matches();
    match cmd.subcommand() {
        Some(("encrypt", sub_matches)) => encrypt(xdg_dirs, sub_matches).await,
        Some(("decrypt", sub_matches)) => decrypt(xdg_dirs, sub_matches).await,
        Some(("old", sub_matches)) => old::old(xdg_dirs, sub_matches).await,
        Some(("watch", _)) => watch::watch(xdg_dirs, "ola").await,

        Some(("login", _)) => login(xdg_dirs).await,
        Some(("register", _)) => register(xdg_dirs).await,
        _ => unreachable!(),
    }
}
