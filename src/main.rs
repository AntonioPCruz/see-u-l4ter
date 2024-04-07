use chrono::{NaiveDateTime, TimeZone};
use clap::{arg, builder::OsStr, parser::ValueSource, Arg, Command};
use regex::Regex;
use server::str_of_date;
use std::fs::File;
use std::io::Write;
use std::io::{BufRead, BufReader, BufWriter};
use std::path::PathBuf;
use std::process::exit;
mod client;
mod server;
// mod cli::watch;
const FORMAT_STR: &str = "%M:%H:%d-%m-%Y";
const EMAIL_REGEX_PATTERN: &str = r#"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"#;

struct User {
    email: String,
}

fn cli() -> Command {
    let encrypt = Command::new("encrypt")
        .short_flag('e')
        .about("Encrypt something")
        .arg(arg!(<FILE_NAME> "The file you wish to encrypt"))
        .arg(Arg::new("timestamp")
            .help("Optional: MIN:HOUR:DAY-MONTH-YEAR. If this is not provided, it will be encrypted with the current time.")
            .required(false)
            .default_value(OsStr::from(str_of_date(chrono::Local::now())))
        )
        .arg_required_else_help(true);

    let decrypt = Command::new("decrypt")
        .short_flag('d')
        .about("Decrypt something")
        .arg(arg!(<FILE_NAME> "The file you wish to decrypt"))
        .arg(Arg::new("key")
            .help("Optional: SHA256/512 key. If this is not provided, the system will try to decrypt the file with a key generated with the current time.")
            .required(false)
            .default_value(OsStr::from(str_of_date(chrono::Local::now())))
        )
        .arg_required_else_help(true);

    Command::new("see-u-l4ter")
        .about("")
        .subcommand_required(true)
        .subcommand(Command::new("server").about("Run the API web server"))
        .subcommand(Command::new("client").about("Run some client, not sure yet!"))
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
        Some(config) => {
            println!("{:?}", config);
            extract_email(config)
        }
        None => {
            let email_regex = Regex::new(EMAIL_REGEX_PATTERN).unwrap();
            let config_path = xdg_dirs
                .place_config_file("config.ini")
                .expect("Couln't place config file in xdg folder");

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
        Some(("encrypt", sub_matches)) => {
            let f = sub_matches.get_one::<String>("FILE_NAME").unwrap();
            let t = sub_matches.get_one::<String>("timestamp").unwrap();
            match sub_matches.value_source("timestamp") {
                Some(ValueSource::DefaultValue) => println!("file: {}, timestamp = {}", f, t),
                Some(ValueSource::CommandLine) => {
                    let dt = chrono::Local::now();
                    let offset = dt.offset();

                    if let Ok(naive) = NaiveDateTime::parse_from_str(t, FORMAT_STR) {
                        let t: chrono::DateTime<<chrono::FixedOffset as TimeZone>::Offset> =
                            chrono::DateTime::from_naive_utc_and_offset(naive, *offset);

                        println!("file: {}, timestamp = {}", f, str_of_date(t.into()));
                    } else {
                        eprintln!(
                        "ERROR: The date string is not in the correct format! Try MIN:HOUR:DAY-MONTH-YEAR"
                    );
                    }
                }
                _ => unreachable!(),
            }
        }
        Some(("decrypt", _sub_matches)) => {
            println!("Hello from decrypt command! :)");
        }
        Some(("server", _sub_matches)) => {
            server::server().await;
        }
        Some(("client", _sub_matches)) => {
            client::client().await.unwrap();
        }
        _ => unreachable!(),
    }
}
