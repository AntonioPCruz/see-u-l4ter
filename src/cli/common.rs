use chrono::{Datelike, NaiveDateTime, TimeZone, Timelike};
use std::process::exit;
pub const FORMAT_STR: &str = "%Y-%m-%d-%H:%M";

// Errors out of the program with a nice message
pub fn error_out(s: &str) {
    println!("\x1b[1;31mERROR: \x1b[0m{}", s); // Red and Bold ERROR
    exit(1);
}

pub fn success(s: &str) {
    println!("\x1b[1;32mSuccess! \x1b[0m{}", s)
}

pub fn str_of_date(d: chrono::DateTime<chrono::Local>) -> String {
    format!(
        "{}:{:02}:{:02}:{:02}:{:02}",
        d.year(),
        d.month(),
        d.day(),
        d.hour(),
        d.minute()
    )
}
