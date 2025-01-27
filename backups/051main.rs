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

        let (RU_uname, RU_pass) = config.credentials.User.flatten();
        logga(&format!("Regular User Key: {}", RU_uname));
        logga(&format!("Regular User Secret: {}", RU_pass));

        let SU_creds = &config.credentials.SuperUser;
        
        let (SU_uname, SU_pass) = if SU_creds.API_key.is_empty() || SU_creds.API_secret.is_empty() {
            ("".to_string(), "".to_string())
        } else {
            SU_creds.flatten()
        };

        if SU_uname.is_empty() && SU_pass.is_empty() {
            logga("Super User Credentials not available");
        } else {
            logga(&format!("Super User Key: {}", SU_uname));
            logga(&format!("Super User Secret: {}", SU_pass));
        }

        if config.has_versioning{
            logga("Versioning available. Generating calls to implement API9:2023 - Improper Inventory Management");
            let (prep_status, version_calls) = prepareVersioningCalls(Some(config));

            if prep_status == ALL_OK {
                logga(&format!("Versioning calls generated: {}", version_calls.len()));
                calls.extend(version_calls); 

                for call in &calls{
                    println!("\n{:?}\n",call);
                }
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
