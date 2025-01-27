// File: sqli_uri_params.rs
// manages the injection on URLs parameters

use crate::types::{HttpTestCase, TestType};
use crate::logger::logga;
use crate::constants::*;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine as _;
use html_escape::encode_safe;
use crate::utils::inflate;
use crate::constants::*;
use crate::payloads::DETECTION_PAYLOADS;
use crate::types::APIConfig;


pub fn generate_escaped_variants(payload: &str) -> Vec<String> {
    vec![
        payload.to_string(), // Originale
        payload.replace(" ", "/**/"), // Spazi trasformati in commenti
        payload.replace("OR", "O/**/R"), // Offuscamento di OR
        payload.replace("AND", "A/**/ND"), // Offuscamento di AND
        payload.replace("UNION", "UNI/**/ON"), // Offuscamento di UNION
        payload.replace("SELECT", "S/**/ELECT"), // Offuscamento di SELECT
    ]
}

pub fn generate_detection_payloads() -> Vec<String> {
    let mut all_payloads = Vec::new();

    for payload in DETECTION_PAYLOADS {
        let variants = generate_escaped_variants(payload);
        all_payloads.extend(variants);
    }

    all_payloads
}

pub fn apply_encodings(payload: &str) -> Vec<String> {
    vec![
        payload.to_string(),                                                                // Originale
        utf8_percent_encode(payload, NON_ALPHANUMERIC).to_string(),                         // URL Encoding
        html_escape::encode_safe(payload).to_string(),                                      // HTML Encoding
        base64::encode(payload),                                                            // Base64
        URL_SAFE.encode(payload),                                                           // Base64 URL-Safe
        payload.chars().map(|c| format!("\\u{:04X}", c as u32)).collect::<String>(),        // Unicode Escaping
    ]
}


pub fn URL_credentials_SQLi(configRecord: Option<APIConfig>, ParamVals:bool) -> (u32, Vec<HttpTestCase>) {
    let mut calls: Vec<HttpTestCase> = Vec::new();
    let mut internal_status = ALL_OK;

    if let Some(config) = configRecord {
        logga("Preparing SQLi on URL Parameters Credentials");
        let base_url = &config.API_structure;
        let key_var = &config.API_KEY_VAR.varname;
        let secret_var = &config.API_SECRET_VAR.varname;

        logga(&format!("Base URL: {}", base_url));
        logga(&format!("Key variable: {}", key_var));
        logga(&format!("Secret variable: {}", secret_var));

        let key_value = if ParamVals {
            config.credentials.User.API_key.clone()
        } else {
            DUMMY_PARAM.to_string()
        };

        let secret_value = if ParamVals {
            config.credentials.User.API_secret.clone()
        } else {
            DUMMY_PARAM.to_string()
        };

        let all_SQLi_payloads = generate_detection_payloads();

        // Creazione test cases con encoding
        for payload in &all_SQLi_payloads {
            // Applica i vari encoding
            let encoded_payloads = apply_encodings(payload);

            for encoded_payload in encoded_payloads {
                // Testa `API_key`
                let test_url_key = inflate(base_url, key_var, &encoded_payload);
                calls.push(HttpTestCase {
                    actual_url: test_url_key,
                    test_type: TestType::SQLi,
                    description: format!("SQLi test on {} with payload: {}", key_var, encoded_payload),
                    payload: Some(encoded_payload.clone()),
                    auth_method: Some("URI".to_string()),
                });

                // Testa `API_secret`
                let test_url_secret = inflate(base_url, secret_var, &encoded_payload);
                calls.push(HttpTestCase {
                    actual_url: test_url_secret,
                    test_type: TestType::SQLi,
                    description: format!("SQLi test on {} with payload: {}", secret_var, encoded_payload),
                    payload: Some(encoded_payload.clone()),
                    auth_method: Some("URI".to_string()),
                });
            }
        }

        logga(&format!("Generated {} SQLi test cases", calls.len()));
    } else {
        logga("Configuration record not available. Exiting SQLi fuzzing.");
        internal_status = NO_CONFIG_RCD;
    }

    (internal_status, calls)
}