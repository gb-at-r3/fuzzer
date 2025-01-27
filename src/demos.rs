use crate::types::HttpTestCase;
use colored::*;

pub fn demo_20250129(
    versionchecks: Vec<HttpTestCase>,
    sqlinjections: Vec<HttpTestCase>,
    fuzzed_creds: Vec<HttpTestCase>,
) {
    println!("{}", "\n=== Demo: 2025-01-29 ===".bold().blue());

    // API9:2023
    println!("{}", "\nVersioning Attacks (API 2023:9):".bold().yellow());
    for (i, case) in versionchecks.iter().enumerate() {
        println!(
            "{} {}",
            format!("[{}]", i + 1).bold().green(),
            case.actual_url
        );
    }

    // API8:2019
    println!("{}", "\nSQL Injection Attacks (API8:2019):".bold().yellow());
    for (i, case) in sqlinjections.iter().enumerate() {
        println!(
            "{} {}",
            format!("[{}]", i + 1 + versionchecks.len()).bold().green(),
            case.actual_url
        );
    }

    // Fuzzing
    println!("{}", "\nFuzzed Credential Attacks:".bold().yellow());
    for (i, case) in fuzzed_creds.iter().enumerate() {
        println!(
            "{} {}",
            format!("[{}]", i + 1 + versionchecks.len() + sqlinjections.len()).bold().green(),
            case.actual_url
        );
    }

    // Conteggio finale
    let total_payloads =
        versionchecks.len() + sqlinjections.len() + fuzzed_creds.len();
    println!(
        "\n{}",
        format!("{} payloads", total_payloads).bold().cyan()
    );
    println!(
        "{}",
        format!("{} versioning attacks (API 2023:9)", versionchecks.len())
            .bold()
            .yellow()
    );
    println!(
        "{}",
        format!("{} SQLinjections (API8:2019)", sqlinjections.len())
            .bold()
            .yellow()
    );
    println!(
        "{}",
        format!("{} Fuzzing credentials", fuzzed_creds.len())
            .bold()
            .yellow()
    );

    println!("{}", "\n=== End of Demo ===".bold().blue());
}