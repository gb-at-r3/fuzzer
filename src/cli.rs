// File: cli.rs
// manages the command line interface

use clap::{Arg, Command, value_parser};
use std::collections::HashMap;

use colored::*;

use crate::types::*;
use crate::json_handler::*;

pub fn warm_up(){
    println!("\n\n{}", "================================================".green());
    println!("{} {}", "FUZZER".bold().yellow(), env!("CARGO_PKG_VERSION"));
    println!("{} {}", "2025 - Gabriele Biondo".italic().cyan(), "<<dopo ci metto la mail>>".italic());
    println!("{}", "================================================".green());
    // let (sts,pld) = loadSQLpayloads();
    // (sts,pld)
}


pub fn parse_arguments() -> clap::ArgMatches {
    Command::new("fuzzer")
        .disable_version_flag(true)
        .disable_help_flag(true)
        .version(env!("CARGO_PKG_VERSION"))
        .about("API Fuzzer CLI Tool")
        .author("Gabriele Biondo")
        .arg(Arg::new("inputfile")
            .short('i')
            .long("inputfile")
            .value_name("FILE")
            .help("Specifies JSON config file")
            .required(true)
            .value_parser(value_parser!(String))
            .num_args(1))
        .arg(Arg::new("verbosity")
            .short('l')
            .long("verbosity")
            .value_name("LEVEL")
            .help("Specifies verbosity level (0, 1, 2, 3)")
            .required(false)
            .num_args(1)
            .value_parser(value_parser!(u8).range(0..=3)))
        .arg(Arg::new("version")
            .long("version")
            .help("Shows the version")
            .action(clap::ArgAction::SetTrue))
        .arg(Arg::new("help")
            .long("help")
            .help("Displays this help message")
            .action(clap::ArgAction::SetTrue))
        .get_matches()
}

pub fn process_arguments(matches: &clap::ArgMatches) -> HashMap<String, String> {
    let mut results = HashMap::new();

    if let Some(inputfile) = matches.get_one::<String>("inputfile") {
        results.insert("inputfile".to_string(), inputfile.clone());
    }

    if let Some(verbosity) = matches.get_one::<u8>("verbosity") {
        results.insert("verbosity".to_string(), verbosity.to_string());
    } else {
        results.insert("verbosity".to_string(), "0".to_string());
    }

    if matches.get_flag("version") {
        results.insert("version".to_string(), "true".to_string());
        
    } else {
        results.insert("version".to_string(), "false".to_string());
    }

    if matches.get_flag("help") {
        results.insert("help".to_string(), "true".to_string());
    } else {
        results.insert("help".to_string(), "false".to_string());
    }

    results
}

pub fn print_help(){
    println!("Usage: fuzzer [OPTIONS] --inputfile <FILE>\n");
    println!("Options:");
    println!("  -i, --inputfile <FILE>  Specifies JSON config file");
    println!("  -l, --verbosity <LEVEL> Specifies verbosity level (0, 1, 2, 3)");
    println!("  --version           Shows the version");
    println!("  --help              Displays this help message");
}