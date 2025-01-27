use std::time::{Instant, Duration};
use tokio;
use futures::future::join_all;
use reqwest::Client;

use std::fs;

mod cli; 
mod json_handler;
mod logger;
mod constants;


use cli::{parse_arguments, process_arguments, print_help, warm_up}; 
use std::collections::HashMap;
use json_handler::load_json;
use constants::*;
use logger::logga;
mod types;

mod payloads;
use payloads::versions_payload;

use crate::json_handler::load_json_as_struct;
use crate::types::APIConfig;
use crate::types::{HttpTestCase, TestType};


mod versioning_handler;
use versioning_handler::{splitVer, prepareVersioningCalls};



pub fn dispatch(configRecord: Option<APIConfig>) -> (u32,Vec<HttpTestCase>){
    let mut calls: Vec<HttpTestCase> = Vec::new();
    let mut internal_status = ALL_OK;

    if let Some(config) = configRecord{    
        
        logga("Starting dispatch process...");

        if config.has_versioning{
            logga("Versioning available. Generating calls to implement API9:2023 - Improper Inventory Management");
            let (prep_status, version_calls) = prepareVersioningCalls(Some(config));

            if prep_status == ALL_OK {
                logga(&format!("Versioning calls generated: {}", version_calls.len()));
                calls.extend(version_calls); 
            } else {
                logga(&format!("Error during versioning preparation: {}", prep_status));
                internal_status = prep_status;
                return (internal_status,calls);
            }

        } else {
            logga("Versioning not present.");
        }

        return (internal_status,calls);
    } else {
        logga("Configuration record not available. Now quitting");
        return (NO_CONFIG_RCD,calls);
    }
}

// pub fn splitVer(anURI: &str, version_variable_name: &str) -> (String, String, String) {
//     // Costruisce il pattern da cercare nella URL
//     let var_pattern = format!("{version_variable_name}");

//     // Trova la posizione del pattern
//     let pos = anURI.find(&var_pattern).expect("Variable not found in URI");

//     // Divide la stringa in prologo e resto
//     let prolog = anURI[..pos].to_string();
//     let rest = &anURI[pos..];

//     // Variabili per contenere la parte centrale e l'epilogo
//     let mut variable = rest.to_string();
//     let mut epilog = String::new();

//     // Trova la fine della variabile nella stringa rimanente
//     if let Some(end_pos) = rest.find(&['/', '?'][..]) {
//         variable = rest[..end_pos].to_string(); // Prende solo la parte della variabile
//         epilog = rest[end_pos..].to_string();   // Prende il resto come epilogo
//     }

//     // Log per debugging
//     logga(&format!(
//         "splitVer completed. Prolog: '{}', Variable: '{}', Epilog: '{}'",
//         prolog, variable, epilog
//     ));

//     // Ritorna il risultato diviso in 3 parti
//     (prolog, variable, epilog)
// }






// pub fn prepareVersioningCalls(configRecord: Option<APIConfig>) -> (u32, Vec<HttpTestCase>) {
//     let mut retCode = ALL_OK;
//     let mut vervals: u32 = 0;
//     let mut retVal: Vec<HttpTestCase> = Vec::new();
//     let mut version_variable_name = String::new();

//     logga("Started parsing version variable...");

//     // Controlla se config esiste
//     if let Some(config) = configRecord {
//         // Cerca la variabile di versione
//         for v in &config.variable_domains {
//             if v.domain == "versions" {
//                 vervals += 1;

//                 if vervals == 1 {
//                     version_variable_name = v.variable.clone();
//                 } else {
//                     logga("Ended parsing version variable: too many Versions Variables");
//                     logga("Now quitting");
//                     return (TOO_MANY_VAR_VER, retVal);
//                 }
//             }
//         }

//         // Nessuna variabile di versione trovata
//         if vervals == 0 {
//             logga("Ended parsing version variable.");
//             logga("Versioning is supposed to be present, but there is no reference to the variable");
//             return (MISSING_VER_VAR, retVal);
//         }

//         // Verifica che la variabile di versione sia presente nella struttura URL
//         if config.API_structure.contains(&version_variable_name) {
//             logga("Finished parsing version variable.");
//             let (prolog, variable, epilog) = splitVer(&config.API_structure, &version_variable_name);

//             logga(&format!(
//                 "splitVer completed. Prolog: '{}', Variable: '{}', Epilog: '{}'",
//                 prolog, variable, epilog
//             ));

//             // Genera URL sia per versioni pure che prefissate
//             for version in &versions_payload {
//                 // Versione pura
//                 let new_url = format!("{}{}{}", prolog, version, epilog);
//                 logga(&format!(
//                     "Generated URL for version {}: {}",
//                     version, new_url
//                 ));

//                 retVal.push(HttpTestCase {
//                     actual_url: new_url,
//                     test_type: TestType::Versioning,
//                     description: format!("Testing version {}", version),
//                     payload: None,
//                     auth_method: None,
//                 });

//                 // Versione prefissata
//                 let prefixed_version = format!("{}{}", version_variable_name, version);
//                 let prefixed_url = format!("{}{}{}", prolog, prefixed_version, epilog);
//                 logga(&format!(
//                     "Generated URL for prefixed version {}: {}",
//                     prefixed_version, prefixed_url
//                 ));

//                 retVal.push(HttpTestCase {
//                     actual_url: prefixed_url,
//                     test_type: TestType::Versioning,
//                     description: format!("Testing prefixed version {}", prefixed_version),
//                     payload: None,
//                     auth_method: None,
//                 });
//             }
//         } else {
//             logga("Ended parsing version variable.");
//             logga("Mismatch version variable and version in the URL");
//             return (MISSING_VERSION, retVal);
//         }
//     }

//     (retCode, retVal)
// }




struct Rez{
    internal_status:u32,
    start_time: Instant,
    end_time: Instant,
    duration: Duration,
    query: String,
    payload: String,
    JWT:String,
    http_status: u16,
    raw_response: String,
}


async fn call(s: &String) -> Rez {
    
    let m1 = format!("Received: {}", s);
    logga(&m1);

    let client = match Client::builder().build() {
        Ok(client) => {
            let m2 = format!("Client created - can go on");
            logga(&m2);
            client
        }
        Err(e) => {
            let m2 = format!("Client could not be created - error: {}",e);
            logga(&m2);
            return Rez{
                internal_status:CLIENT_ERROR,
                start_time: Instant::now(),
                end_time: Instant::now(),
                duration: Duration::from_secs(0),
                query: s.clone(),
                payload: String::new(),
                JWT: String::new(),
                http_status: 500,
                raw_response: format!("Client Error: {}", e),
            }
        }
    };

    let ora = Instant::now();
    let request = client.request(
        reqwest::Method::GET,
        s,
    );

    let mut body = String::new();

    match request.send().await {
        Ok(resp) => {
            match resp.text().await {
                Ok(text) => {
                    logga(&format!("Response: {}", text));
                    body = text
                }
                Err(e) => {
                    let m4 = format!("Error - cannot read body: {}", e);
                    logga(&m4);
                    return Rez {
                        internal_status: REQUEST_ERROR,
                        start_time: ora,
                        end_time: Instant::now(),
                        duration: Duration::from_secs(0),
                        query: s.clone(),
                        payload: String::new(),
                        JWT: String::new(),
                        http_status: 500,
                        raw_response: format!("Body Error: {}", e),
                    };
                }
            }
        }
        Err(e) =>{
            let m4 = format!("Request Error: {}", e);
            logga(&m4);
            return Rez {
                internal_status: REQUEST_ERROR,
                start_time: ora,
                end_time: Instant::now(),
                duration: Duration::from_secs(0),
                query: s.clone(),
                payload: String::new(),
                JWT: String::new(),
                http_status: 500,
                raw_response: format!("Request Error: {}", e),
            };
        }
    };

    let dopo = Instant::now();
    let durata = dopo.duration_since(ora);

    Rez {
        start_time: ora,
        end_time: dopo,
        duration: durata,
        query: s.clone(),
        payload: String::new(),
        JWT: String::new(),
        http_status: 200,
        raw_response: body,
        internal_status: ALL_OK,
    }
}



#[tokio::main]
async fn main() {
    let mut status = ALL_OK;

    warm_up();
    let matches = parse_arguments();

    if matches.get_flag("version") {
        println!("fuzzer {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    if matches.get_flag("help") {
        print_help();
        return;
    }

    let results = process_arguments(&matches);

    // println!("{:#?}", results); QUESTO POI LO LEGO ALLA VERBOSITY


    if let Some(filename) = results.get("inputfile") {
        logga(&format!("Loading File: {}", filename));
        let (config, load_status) = load_json_as_struct(filename);
        status = load_status;

        if status == ALL_OK {
            logga(&format!("JSON file loaded into struct"));

            // Esempio di accesso ai dati
            if let Some(config) = config {
                logga(&format!("API Nickname: {}", config.API_Nickname));
                logga(&format!("Auth methods: {:?}", config.auth_methods));

                // // Itera sulle variabili
                // for var in &config.variable_domains {
                //     logga(&format!("Variabile: {}, Dominio: {}", var.variable, var.domain));
                // }

                let (status, URIlist) = dispatch(Some(config));
            }
        }

    } else {
        logga(&format!("No input file"));
        status = NO_INPUT_FILE;    
    }

    logga(&format!("Execution finished with status: {}", status));


    // LA PARTE QUI SOTTO VA BENE E FUNZIONA PERFETTAMENTE
    // let mut fuzzed = vec![
    //     "https://rest.nexmo.com/account/get-balance?api_key=970f0ff6&api_secret=Th1s-I5-my_n3w-s3cr3t".to_string(),
    // ];

    // // Logging iniziale
    // let m1 = String::from("Starting Async calls");
    // logga(&m1);

    // // Usa map con blocco per aggiungere log e debugging
    // let futures = fuzzed.iter().map(|item| {
    //     let m2 = format!("Request: {}", item);
    //     logga(&m2); // Log ogni chiamata
    //     let future = call(item); // Esegue la chiamata async
    //     let m3 = format!("Chiamata inviata per: {}", item);
    //     logga(&m3);
    //     future // Restituisce la future
    // });

    // // Esegui tutte le chiamate in parallelo
    // let results: Vec<Rez> = join_all(futures).await;

    // // Log finale
    // println!("Tutte le chiamate sono completate.");
    // for rez in &results {
    //     println!("Risultato ricevuto: {}", rez.query); // Supponendo che 'query' sia accessibile
    // }
    // FINE PARTE CHE FUNZIONA PERFETTAMENTE



}
