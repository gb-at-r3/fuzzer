// File: utils.rs
// Utilities

use regex::Regex;

pub fn inflate(the_url: &String, var_name: &String, var_value: &String) -> String {
    let pattern = format!(r"([?&]{}=)[^&]*", regex::escape(var_name));
    let replacement = format!("${{1}}{}", var_value);

    regex::Regex::new(&pattern)
        .unwrap()
        .replace(the_url, replacement)
        .to_string()
}