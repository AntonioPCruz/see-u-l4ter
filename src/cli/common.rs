use chrono::{Datelike, Timelike};
use serde::Deserialize;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::exit;
use chrono::{NaiveDateTime, TimeZone};

pub const FORMAT_STR: &str = "%Y-%m-%d-%H:%M";
pub const EMAIL_REGEX_PATTERN: &str = r#"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"#;

// Errors out of the program with a nice message
pub fn error_out(s: &str) {
    println!("\x1b[1;31mERROR: \x1b[0m{}", s); // Red and Bold ERROR
    exit(1);
}

pub fn success(s: &str) {
    println!("\x1b[1;32mSuccess! \x1b[0m{}", s)
}

pub fn str_of_date(d: chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "{}-{:02}-{:02}-{:02}:{:02}",
        d.year(),
        d.month(),
        d.day(),
        d.hour(),
        d.minute()
    )
}

pub fn str_of_date_local(d: chrono::DateTime<chrono::Local>) -> String {
    format!(
        "{}-{:02}-{:02}-{:02}:{:02}",
        d.year(),
        d.month(),
        d.day(),
        d.hour(),
        d.minute()
    )
}

pub fn str_to_utc_string(t: String) -> String {
    let dt = chrono::Utc::now().with_second(0).expect("Couldt change second").with_nanosecond(0).expect("Couldnt change nano");

    println!("{}", dt);

    if let Ok(naive) = NaiveDateTime::parse_from_str(&t, FORMAT_STR) {
        let t = chrono::Local.from_local_datetime(&naive)
            .latest()
            .expect("Failed to convert to local datetime")
            .with_timezone(&chrono::Utc);
        println!("{}", t);
        if t < dt {
            error_out("The date can't be less than the time right now!")
        }

        str_of_date(t)
    } else {
        error_out(
            "The date string is not in the correct format! Try YEAR-MONTH-DAY-HOUR:MIN",
        );
        unreachable!()
    }
}

pub fn write_to_config_file(xdg_dirs: xdg::BaseDirectories, left: String, right: String) {
    fn write_it(path: PathBuf, left: String, right: String) {
        // Open the file for reading and writing
        let file = std::fs::File::open(&path).expect("Couldn't open file");
        let reader = BufReader::new(&file);
        let mut lines = reader
            .lines()
            .map(|l| l.expect("Failed to read line"))
            .collect::<Vec<_>>();

        // Check if there's already a line starting with "left ="
        let mut left_exists = false;
        for line in &mut lines {
            if line.starts_with(&format!("{} =", left)) {
                *line = format!("{} = {}", left, right); // Replace the value
                left_exists = true;
                break;
            }
        }

        // If there wasn't a line with "left =", add it to the end of the file
        if !left_exists {
            lines.push(format!("{} = {}", left, right));
        }

        // Write the modified lines back to the file
        let file = std::fs::File::create(&path).expect("Could not create file");
        let mut writer = BufWriter::new(file);
        for line in lines {
            writeln!(writer, "{}", line).expect("Failed to write line");
        }
    }

    match xdg_dirs.find_config_file("config.ini") {
        Some(config) => write_it(config, left, right),
        None => {
            let config_path = xdg_dirs
                .place_config_file("config.ini")
                .expect("Couldn't place config file in xdg folder");

            let _ = std::fs::File::create(&config_path).expect("Couldn't create file");
            write_it(config_path, left, right)
        }
    };
}

pub fn read_from_config_file(xdg_dirs: xdg::BaseDirectories, left: String) -> String {
    fn read_it(path: PathBuf, left: String) -> String {
        // Open the file for reading
        let file = std::fs::File::open(&path).expect("Couldn't open file");
        let reader = BufReader::new(file);

        // Iterate over each line in the file
        for line in reader.lines() {
            if let Ok(line) = line {
                // Check if the line starts with "left ="
                if line.starts_with(&format!("{} =", left)) {
                    // If it does, return the value after "left ="
                    return line
                        .split('=')
                        .nth(1)
                        .expect("No 1th value")
                        .trim()
                        .to_string();
                }
            }
        }
        // If no line starts with "left =", return None
        panic!("No token!")
    }

    match xdg_dirs.find_config_file("config.ini") {
        Some(config) => read_it(config, left),
        None => {
            let config_path = xdg_dirs
                .place_config_file("config.ini")
                .expect("Couldn't place config file in xdg folder");

            read_it(config_path, left)
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct AuthBody {
    pub access_token: String,
    pub token_type: String,
}

#[derive(Debug, Deserialize)]
pub struct KeyBody {
    pub key: String,
}
