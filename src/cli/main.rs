mod common;
use chrono::{Datelike, NaiveDateTime, TimeZone, Timelike};
use clap::{arg, builder::OsStr, parser::ValueSource, Arg, Command};
use encrypt::encrypt;
use regex::Regex;
use reqwest::Client;
use serde_json::json;
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    path::PathBuf,
    process::exit,
};
mod encrypt;

const EMAIL_REGEX_PATTERN: &str = r#"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"#;

struct User {
    email: String,
}

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
        .subcommand(Command::new("gen").about("Generate a key for a given time-stamp"))
        .subcommand(Command::new("config").about("Configure your email and password"))
}

fn extract_email(path: PathBuf) -> User {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let mut email = String::new();

    let email_regex = Regex::new(EMAIL_REGEX_PATTERN).unwrap();

    for line in reader.lines() {
        let line = line.unwrap();
        for e in email_regex.find_iter(&line) {
            email = e.as_str().to_string();
        }
    }
    if email.is_empty() {
        eprintln!("ERROR: Email could not be read!\nPlease run 'see-u-l4ter config' to change your email, or edit the config.ini file in your XDG_CONFIG_HOME/see-u-l4ter folder.");
        exit(1);
    }

    User { email }
}

#[tokio::main]
async fn main() {
    let xdg_dirs =
        xdg::BaseDirectories::with_prefix("see-u-l4ter").expect("Coudln't get xdg folder");
    let user = match xdg_dirs.find_config_file("config.ini") {
        Some(config) => extract_email(config),
        None => {
            let email_regex = Regex::new(EMAIL_REGEX_PATTERN).unwrap();
            let config_path = xdg_dirs
                .place_config_file("config.ini")
                .expect("Couldn't place config file in xdg folder");

            println!("Welcome to see-u-l4ter! As this is your first time starting the program, kindly provide us with your email:");
            loop {
                println!("Enter an email address:");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();

                input = input.as_str().trim().to_string();

                if email_regex.is_match(&input) {
                    println!("Valid email address: {}", input);
                    let file = File::create(config_path).unwrap();
                    let mut writer = BufWriter::new(file);
                    let line = format!("email = {}", input);
                    writeln!(writer, "{}", line).unwrap();
                    println!("Your email has been set to: {}", input);

                    break User { email: input };
                } else {
                    println!("Invalid email address, please try again.");
                }
            }
        }
    };
    let cmd = cli().get_matches();
    match cmd.subcommand() {
        Some(("encrypt", sub_matches)) => encrypt(sub_matches).await,
        Some(("decrypt", _sub_matches)) => {
            println!("Hello from decrypt command! :)");
        }
        _ => unreachable!(),
    }
}
