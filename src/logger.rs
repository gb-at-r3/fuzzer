// File: logger.rs
// Implements a basic logging feature. To be expanded, according to verbosity

use chrono::Local;

pub fn logga(my_str: &str) {
    let ora = Local::now();
    println!("[{}] - {}", ora.format("%Y-%m-%d %H:%M:%S"), my_str);
}
