mod cli; 
mod json_handler;
mod logger;
mod constants;
mod types;
mod versioning_handler;
mod payloads;



use std::time::{Instant, Duration};
use serde_json::to_string;
use tokio;
use futures::future::join_all;
use reqwest::Client;
use regex::Regex;
use types::*;
use html_escape::encode_safe;
use payloads::*;
use crate::json_handler::load_json_as_struct;
use crate::types::APIConfig;
use crate::types::{HttpTestCase, TestType};
use versioning_handler::*;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC}; // URL encoding
use base64; // Base64 encoding
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine as _;
use constants::*;
use logger::logga;
use cli::{parse_arguments, process_arguments, print_help, warm_up}; 
use std::collections::HashMap;
use json_handler::load_json;
use std::any::type_name;
// use std::fs;

mod sqli_uri_params;
use sqli_uri_params::{URL_credentials_SQLi, apply_encodings, generate_detection_payloads, generate_escaped_variants};
mod utils;
use utils::inflate;

//DEMOS
mod demos;
use demos::demo_20250129;

// DEBUG


fn print_type_of<T>(_: &T) {
    println!("{}", type_name::<T>());
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

// pub fn inflate(the_url: &String, var_name: &String, var_value: &String) -> String {
//     let pattern = format!(r"([?&]{}=)[^&]*", regex::escape(var_name));
//     let replacement = format!("${{1}}{}", var_value);

//     regex::Regex::new(&pattern)
//         .unwrap()
//         .replace(the_url, replacement)
//         .to_string()
// }

fn create_auth_test_case(the_url:&String,
                         key_name:&String,
                         key_value:&String,
                         secret_name:&String,
                         secret_value:&String,
                         type_of_test:TestType,
                         pld: Option<String>,
                         method_of_auth: Option<String>,
                         test_description:&str)->HttpTestCase{
    let mut temp_url: String;
        // pub struct HttpTestCase {
        //     actual_url: String,
        //     test_type: TestType,
        //     description: String,
        //     payload: Option<String>,
        //     auth_method: Option<String>,
        // }

    temp_url = inflate(the_url, key_name, key_value);
    temp_url = inflate(&temp_url, secret_name, secret_value);

    return HttpTestCase{
        actual_url: temp_url,
        test_type:type_of_test,
        payload: pld,
        auth_method: method_of_auth,
        description:test_description.to_string(),
    }
}

pub fn URL_creds_auth_fuzzing(the_url:&String,key_name:&String,key_value:&String,secret_name:&String,secret_value:&String)->Vec<HttpTestCase>{
    let mut result:Vec<HttpTestCase>=Vec::new();
    // CASES
    // valid credentials
    // wrong credentials
    // missing key
    // missing secret
    // missing key and secret
    // missing authentication at all (No API_key=... and No API_Secret = ...)
    let mut tempCase: HttpTestCase;
    let mut tempURL= String::new();
    let mut description = String::new();
    let mut type_of_test= TestType::Baselining;
    let mut pld =None;
    let method_of_auth=Some("URI".to_string());
    let mut fuzzed_key = String::from("Blatantly-wrong-key");
    let mut fuzzed_secret = String::from("Blatantly-wrong-secret");
    
    // CASE 1: valid credentials
    description = "Baselining test - all correct".to_string();
    tempCase = create_auth_test_case(the_url, key_name, key_value, secret_name, secret_value, type_of_test.clone(), pld.clone(), method_of_auth.clone(), &description);
    result.push(tempCase);
    //CASE 2: blatantly wrong credentials
    description = "Baselining test - blatantly wrong credentials".to_string();
    tempCase = create_auth_test_case(the_url, key_name, &fuzzed_key, secret_name, &fuzzed_secret, type_of_test.clone(), pld.clone(), method_of_auth.clone(), &description);
    result.push(tempCase);
    // CASE 3: missing key
    description = "Baselining test - missing API_key".to_string();
    fuzzed_key = String::new();
    fuzzed_secret = secret_value.clone();
    tempCase = create_auth_test_case(the_url, key_name, &fuzzed_key, secret_name, &fuzzed_secret, type_of_test.clone(), pld.clone(), method_of_auth.clone(), &description);
    result.push(tempCase);
    // CASE 4: missing secret
    description = "Baselining test - missing API_secret".to_string();
    fuzzed_key = key_value.clone();
    fuzzed_secret = String::new();
    tempCase = create_auth_test_case(the_url, key_name, &fuzzed_key, secret_name, &fuzzed_secret, type_of_test.clone(), pld.clone(), method_of_auth.clone(), &description);
    result.push(tempCase);
    // CASE 5: missing key and secret
    description = "Baselining test - missing both API_secret and API_key".to_string();
    fuzzed_key = String::new();
    tempCase = create_auth_test_case(the_url, key_name, &fuzzed_key, secret_name, &fuzzed_secret, type_of_test.clone(), pld.clone(), method_of_auth.clone(), &description);
    result.push(tempCase);
    // // CASE 6: missing authentication at all
    // description = "Baselining test - no authentication parameters".to_string();
    // let mut stripped_url = the_url.clone(); // Copia l'URL di base

    // // removes both key and secret
    // stripped_url = stripped_url
    // .replace(&format!("&{}={}", key_name, key_value), "")
    // .replace(&format!("&{}={}", secret_name, secret_value), "")
    // .replace(&format!("{}={}&", key_name, key_value), "")
    // .replace(&format!("{}={}", key_name, key_value), "")
    // .replace(&format!("{}={}&", secret_name, secret_value), "")
    // .replace(&format!("{}={}", secret_name, secret_value), "");

    // tempCase = create_auth_test_case(&stripped_url, key_name,&fuzzed_key, secret_name, &fuzzed_secret, type_of_test,pld.clone(), method_of_auth.clone(),&description);
    // result.push(tempCase);

    
    // CASE 6: no authentication at all
    description = "Baselining test - no authentication parameters".to_string();
    let mut stripped_url = the_url.clone();

    // Usa regex per eliminare key e secret
    let re_key = Regex::new(&format!(r"([?&]){}=[^&]*", key_name)).unwrap();
    let re_secret = Regex::new(&format!(r"([?&]){}=[^&]*", secret_name)).unwrap();

    stripped_url = re_key.replace(&stripped_url, "$1").to_string();
    stripped_url = re_secret.replace(&stripped_url, "$1").to_string();

    // Rimuove eventuali ? o & finali residui
    stripped_url = stripped_url.trim_end_matches(['?', '&']).to_string();

    tempCase = create_auth_test_case(
        &stripped_url,
        key_name,
        &"".to_string(),
        secret_name,
        &"".to_string(),
        type_of_test,
        pld.clone(),
        method_of_auth.clone(),
        &description,
    );
    result.push(tempCase);
    

    for R in &result{
        println!("{:#?}", R);
    }

    result

}

// fn URL_credentials_fuzzing(configRecord: Option<APIConfig>)-> (u32, Vec<HttpTestCase>){
//     let mut calls:Vec<HttpTestCase> = Vec::new(); 
//     let mut tempXXX:Vec<HttpTestCase> = Vec::new(); 
//     let mut internal_status = ALL_OK; 
//     if let Some(config) = configRecord {
//         logga("Starting URL credentials fuzzing...");
//         let (user_key, user_secret) = config.credentials.User.flatten();
//         let (su_key, su_secret) = config.credentials.SuperUser.flatten();
//         let key_var = config.API_KEY_VAR.varname.clone();
//         let secret_var = config.API_SECRET_VAR.varname.clone();
//         let base_url = &config.API_structure;
//         let superuser_creds_available = !(su_key.is_empty() && su_secret.is_empty());

//         logga(&format!("Credentials:"));
//         logga(&format!("\tUser - key: {}", user_key));
//         logga(&format!("\tUser - secret: {}", user_secret));
//         if (superuser_creds_available){
//             logga(&format!("\tSuper User - key: {}", su_key));
//             logga(&format!("\tSuper User - secret: {}", su_secret));
//         } else {
//             logga(&format!("Super User Credentials not available"))
//         }
//         logga(&format!("key variable name: {}", key_var));
//         logga(&format!("secret variable name: {}", secret_var));
//         logga(&format!("base url: {}", base_url));

//         let tmp = URL_creds_auth_fuzzing(&base_url,&key_var,&user_key,&secret_var,&user_secret);
//         logga("Finished URL credentials fuzzing.");

//         return (internal_status, calls);
//     } else {
//         logga("Configuration record not available. Now quitting");
//         return (NO_CONFIG_RCD, calls);
//     }
// }

fn URL_credentials_fuzzing(configRecord: Option<APIConfig>) -> (u32, Vec<HttpTestCase>) {
    let mut calls: Vec<HttpTestCase> = Vec::new(); 
    let mut internal_status = ALL_OK; 
    if let Some(config) = configRecord {
        logga("Starting URL credentials fuzzing...");
        let (user_key, user_secret) = config.credentials.User.flatten();
        let key_var = config.API_KEY_VAR.varname.clone();
        let secret_var = config.API_SECRET_VAR.varname.clone();
        let base_url = &config.API_structure;

        logga(&format!("Credentials:"));
        logga(&format!("\tUser - key: {}", user_key));
        logga(&format!("\tUser - secret: {}", user_secret));
        logga(&format!("key variable name: {}", key_var));
        logga(&format!("secret variable name: {}", secret_var));
        logga(&format!("base url: {}", base_url));

        let tmp = URL_creds_auth_fuzzing(base_url, &key_var, &user_key, &secret_var, &user_secret);
        
        logga(&format!("Generated {} credential fuzzing test cases", tmp.len()));
        
        if tmp.is_empty() {
            logga("No fuzzing test cases generated.");
        }

        calls.extend(tmp);

        if calls.is_empty() {
            logga("No credential fuzzing test cases were added to the result.");
        } else {
            logga(&format!("Total fuzzing test cases: {}", calls.len()));
        }

        logga("Finished URL credentials fuzzing.");
        return (internal_status, calls);
    } else {
        logga("Configuration record not available. Now quitting");
        return (NO_CONFIG_RCD, calls);
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



    // if let Some(filename) = results.get("inputfile") {
    //     logga(&format!("Loading File: {}", filename));
    //     let (config, load_status) = load_json_as_struct(filename);
    //     status = load_status;

    //     if status == ALL_OK {
    //         logga(&format!("JSON file loaded into struct"));

    //         // Esempio di accesso ai dati
    //         if let Some(config) = config {
    //             // logga(&format!("API Nickname: {}", config.API_Nickname));
    //             // logga(&format!("Auth methods: {:?}", config.auth_methods));

    //             // // Itera sulle variabili
    //             // for var in &config.variable_domains {
    //             //     logga(&format!("Variabile: {}, Dominio: {}", var.variable, var.domain));
    //             // }

    //             let (status, URIlistCredFuzz) = versioning_test(Some(config.clone()));
    //             let (status, URIlistVerFuzz) = URL_credentials_fuzzing(Some(config.clone()));
    //             if status == ALL_OK{
    //                 let (status, URIListSQLi) = URL_credentials_SQLi(Some(config.clone()), true);

    //                 // DEMO
                    
    //                 demo_20250129(URIlistVerFuzz, URIListSQLi, URIlistCredFuzz);

    //                 // END DEMO

    //             } else {
    //                 //gestire l'errore
    //             }
    //         }
    //     }
    if let Some(filename) = results.get("inputfile") {
        logga(&format!("Loading File: {}", filename));
        let (config, load_status) = load_json_as_struct(filename);
        status = load_status;
    
        if status == ALL_OK {
            logga(&format!("JSON file loaded into struct"));
    
            if let Some(config) = config {
                // Genera i test case di versioning
                let (status_versioning, URIlistVerFuzz) = versioning_test(Some(config.clone()));
                // Genera i test case di fuzzing sulle credenziali
                let (status_fuzzing, URIlistCredFuzz) =
                    URL_credentials_fuzzing(Some(config.clone()));
                // Genera i test case di SQL Injection
                let (status_sqli, URIListSQLi) = URL_credentials_SQLi(Some(config.clone()), true);
    
                // Verifica che tutti i test siano stati generati correttamente
                if status_versioning == ALL_OK
                    && status_fuzzing == ALL_OK
                    && status_sqli == ALL_OK
                {
                    // Passa tutti e tre i vettori alla demo
                    demo_20250129(URIlistVerFuzz, URIListSQLi, URIlistCredFuzz);
                } else {
                    logga("Some tests failed to generate.");
                }
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
