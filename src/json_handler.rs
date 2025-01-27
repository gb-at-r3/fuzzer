// file: json_handler.rs
// manages the API description by loading it.

use std::collections::HashMap;
use std::fs;
use serde_json::Result;
use serde_json::{Value,Map};
use serde_json;

use crate::logger::logga;
use crate::constants::*;
use crate::types::APIConfig;
use crate::types::*;

pub fn load_json(filename: &String) -> (HashMap<String, Value>, u32) {
    let mut status = ALL_OK; // Stato iniziale
    let mut json_map = HashMap::new(); // Mappa vuota di default

    match fs::read_to_string(filename) {
        Ok(data) => match serde_json::from_str::<Value>(&data) {
            Ok(json) => {
                if let Value::Object(map) = json {
                    logga(&format!("JSON loaded"));

                    for (key, value) in map.iter() {
                        json_map.insert(key.clone(), value.clone());
                    }
                } else {
                    logga(&format!("Invalid JSON"));
                    status = INVALID_JSON;
                }
            },
            Err(e) => {
                logga(&format!("JSON Parsing Error: {}", e));
                status = JSON_PARSING_ERROR;
            },
        },
        Err(e) => {
            logga(&format!("Error Loading File: {}", e));
            status = CANNOT_LOAD_JSON;
        },
    }

    (json_map, status)
}

pub fn load_json_as_struct(filename: &String) -> (Option<APIConfig>, u32) {
    let mut status = ALL_OK;

    match fs::read_to_string(filename) {
        Ok(data) => match serde_json::from_str::<APIConfig>(&data) {
            Ok(config) => {
                logga(&format!("JSON loaded into struct"));
                return (Some(config), status);
            }
            Err(e) => {
                logga(&format!("JSON Parsing Error: {}", e));
                status = JSON_PARSING_ERROR;
            }
        },
        Err(e) => {
            logga(&format!("Error Loading File: {}", e));
            status = CANNOT_LOAD_JSON;
        }
    }

    (None, status)
}

// pub fn loadSQLpayloads() -> (u32, Vec<Payload>) {
//     let mut status = ALL_OK;
//     let mut payloads: Vec<Payload> = Vec::new();

//     let filename = "src/resources/classified_payloads_complete.json";

//     logga(&"Loading SQLi Payloads");

//     match fs::read_to_string(filename) {
//         Ok(data) => {
//             match serde_json::from_str::<Vec<Payload>>(&data) {
//                 Ok(loaded_payloads) => {
//                     payloads = loaded_payloads;
//                     logga(&format!("{} SQLi payloads successfully imported",payloads.len()));
//                 }
//                 Err(e) => {
//                     println!("JSON Parsing Error: {}", e);
//                     status = JSON_PARSING_ERROR_PAYLOAD;
//                 }
//             }
//         }
//         Err(e) => {
//             println!("Error Loading File: {}", e);
//             status = CANNOT_LOAD_JSON_PAYLOADS;
//         }
//     }

//     (status, payloads)
// }