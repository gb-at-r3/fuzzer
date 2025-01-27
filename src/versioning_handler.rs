// file: versioning_handler.rs
// Implements API 2023:9

use crate::logger::logga;
use crate::constants::*;
use crate::types::{APIConfig, HttpTestCase, TestType};
use crate::payloads::*;

// use crate::types::{APIConfig, HttpTestCase, TestType};


/// Splits a URL into prolog, variable, and epilog based on the version variable name.
pub fn splitVer(anURI: &str, version_variable_name: &str) -> (String, String, String) {
    let var_pattern = format!("{version_variable_name}");
    let pos = anURI.find(&var_pattern).expect("Variable not found in URI");

    let prolog = anURI[..pos].to_string();
    let rest = &anURI[pos..];
    let mut variable = rest.to_string();
    let mut epilog = String::new();

    if let Some(end_pos) = rest.find(&['/', '?'][..]) {
        variable = rest[..end_pos].to_string();
        epilog = rest[end_pos..].to_string();
    }

    logga(&format!(
        "splitVer completed. Prolog: '{}', Variable: '{}', Epilog: '{}'",
        prolog, variable, epilog
    ));

    (prolog, variable, epilog)
}

/// Prepares HTTP test cases for versioning attacks based on API structure.
pub fn prepareVersioningCalls(configRecord: Option<APIConfig>) -> (u32, Vec<HttpTestCase>) {
    let mut retCode = ALL_OK;
    let mut vervals: u32 = 0;
    let mut retVal: Vec<HttpTestCase> = Vec::new();
    let mut version_variable_name = String::new();

    logga("Started parsing version variable...");

    if let Some(config) = configRecord {
        for v in &config.variable_domains {
            if v.domain == "versions" {
                vervals += 1;

                if vervals == 1 {
                    version_variable_name = v.variable.clone();
                } else {
                    logga("Ended parsing version variable: too many Versions Variables");
                    logga("Now quitting");
                    return (TOO_MANY_VAR_VER, retVal);
                }
            }
        }

        if vervals == 0 {
            logga("Ended parsing version variable.");
            logga("Versioning is supposed to be present, but there is no reference to the variable");
            return (MISSING_VER_VAR, retVal);
        }

        if config.API_structure.contains(&version_variable_name) {
            logga("Finished parsing version variable.");
            let (prolog, variable, epilog) = splitVer(&config.API_structure, &version_variable_name);

            logga(&format!(
                "splitVer completed. Prolog: '{}', Variable: '{}', Epilog: '{}'",
                prolog, variable, epilog
            ));

            for version in &versions_payload {
                let new_url = format!("{}{}{}", prolog, version, epilog);
                logga(&format!("Generated URL for version {}: {}", version, new_url));

                retVal.push(HttpTestCase {
                    actual_url: new_url,
                    test_type: TestType::Versioning,
                    description: format!("Testing version {}", version),
                    payload: None,
                    auth_method: None,
                });

                let prefixed_version = format!("{}{}", version_variable_name, version);
                let prefixed_url = format!("{}{}{}", prolog, prefixed_version, epilog);
                logga(&format!("Generated URL for prefixed version {}: {}", prefixed_version, prefixed_url));

                retVal.push(HttpTestCase {
                    actual_url: prefixed_url,
                    test_type: TestType::Versioning,
                    description: format!("Testing prefixed version {}", prefixed_version),
                    payload: None,
                    auth_method: None,
                });
            }
        } else {
            logga("Ended parsing version variable.");
            logga("Mismatch version variable and version in the URL");
            return (MISSING_VERSION, retVal);
        }
    }

    (retCode, retVal)
}


pub fn handle_versioning_superuser(
    config: &APIConfig, 
    version_calls: &Vec<HttpTestCase>
) -> Vec<HttpTestCase> {
    let key_var = config.API_KEY_VAR.varname.trim().to_string();
    let secret_var = config.API_SECRET_VAR.varname.trim().to_string();
    logga(&format!("API Key variable name: {}", key_var));
    logga(&format!("API Key secret name: {}", secret_var));

    let mut temp: Vec<HttpTestCase> = Vec::new();

    // Estrai credenziali SuperUser
    let SU_creds = &config.credentials.SuperUser;
    let (SU_uname, SU_pass) = if SU_creds.API_key.is_empty() || SU_creds.API_secret.is_empty() {
        ("".to_string(), "".to_string()) // Nessuna credenziale
    } else {
        SU_creds.flatten() // Credenziali valide
    };

    if SU_uname.is_empty() || SU_pass.is_empty() {
        logga("Super User Credentials not found");
        return temp; // Restituisce un vettore vuoto
    }

    logga(&format!("Found super user credentials: {}:{}", SU_uname, SU_pass));

    // Genera i test case per il SuperUser
    for call in version_calls {
        let myURL = set_creds(
            &call.actual_url,
            &SU_uname,
            &SU_pass,
            &key_var,
            &secret_var
        );
        temp.push(HttpTestCase {
            actual_url: myURL,
            test_type: call.test_type.clone(),
            description: format!("(SU) {}", call.description),
            payload: call.payload.clone(),
            auth_method: call.auth_method.clone(),
        });
    }

    temp // Restituisce i test case generati
}



pub fn handle_versioning_user(config: &APIConfig,version_calls: &Vec<HttpTestCase>) -> Vec<HttpTestCase> {
    // Estrai credenziali utente
    let (RU_uname, RU_pass) = config.credentials.User.flatten();
    logga(&format!("Found Regular User Key: {}", RU_uname));
    logga(&format!("Found Regular User Secret: {}", RU_pass));

    let key_var = config.API_KEY_VAR.varname.trim().to_string();
    let secret_var = config.API_SECRET_VAR.varname.trim().to_string();
    logga(&format!("API Key variable name: {}", key_var));
    logga(&format!("API Key secret name: {}", secret_var));

    let mut temp: Vec<HttpTestCase> = Vec::new();

    for call in version_calls {
        logga(&format!("Original URL: {}", call.actual_url));
        logga(&format!(
            "Modifying with: key={} secret={} -> {}:{}",
            key_var, secret_var, RU_uname, RU_pass
        ));

        // Modifica URL con credenziali utente
        let myURL = set_creds(
            &call.actual_url,
            &RU_uname,
            &RU_pass,
            &key_var,
            &secret_var,
        );
        logga(&format!("Obtaining: {}", myURL));

        // Crea nuovo test case aggiornato
        temp.push(HttpTestCase {
            actual_url: myURL,
            test_type: call.test_type.clone(),
            description: call.description.clone(),
            payload: call.payload.clone(),
            auth_method: call.auth_method.clone(),
        });
    }

    // Restituisce il risultato
    temp
}

fn set_creds(
    myURL: &String,
    uname: &String,
    pass: &String,
    key_var: &String,
    secret_var: &String
) -> String {
    let mut url = myURL.clone(); // Copia l'URL originale

    // Sostituisci API_key
    let key_pattern = format!(r"({}=)[^&]*", regex::escape(key_var)); // Match "API_key=qualcosa"
    let key_replacement = format!("${{1}}{}", uname); // Sostituisce solo il valore

    url = regex::Regex::new(&key_pattern)
        .unwrap()
        .replace(&url, key_replacement)
        .to_string();

    // Sostituisci API_secret
    let secret_pattern = format!(r"({}=)[^&]*", regex::escape(secret_var)); // Match "API_secret=qualcosa"
    let secret_replacement = format!("${{1}}{}", pass); // Sostituisce solo il valore

    url = regex::Regex::new(&secret_pattern)
        .unwrap()
        .replace(&url, secret_replacement)
        .to_string();

    url // Restituisce l'URL aggiornato
}


pub fn versioning_test(configRecord: Option<APIConfig>) -> (u32, Vec<HttpTestCase>) {
    let mut calls: Vec<HttpTestCase> = Vec::new(); 
    let mut internal_status = ALL_OK; 

    // Verifica se la configurazione è disponibile
    if let Some(config) = configRecord {
        logga("Starting versioning_test process...");

        // Verifica e log delle credenziali dell'utente regolare
        let (RU_uname, RU_pass) = config.credentials.User.flatten();
        logga(&format!("Found Regular User Key: {}", RU_uname));
        logga(&format!("Found Regular User Secret: {}", RU_pass));

        // Verifica se il versioning è disponibile
        if config.has_versioning {
            logga("Versioning available. Generating calls to implement API9:2023 - Improper Inventory Management");

            // Prepara le chiamate base per il versioning
            let (prep_status, version_calls) = prepareVersioningCalls(Some(config.clone()));

            if prep_status == ALL_OK {
                logga(&format!("Versioning calls generated: {}", version_calls.len()));

                let user_calls = handle_versioning_user(&config, &version_calls);
                calls.extend(user_calls);

                let superuser_calls = handle_versioning_superuser(&config, &version_calls);
                calls.extend(superuser_calls);

                logga(&format!("Total calls after adding credentials: {}", calls.len()));
                for call in &calls {
                    println!("\n{:?}\n", call); // Stampa ogni chiamata
                }
            } else {
                logga(&format!("Error during versioning preparation: {}", prep_status));
                internal_status = prep_status;
                return (internal_status, calls); // Ritorna subito in caso di errore
            }
        } else {
            logga("Versioning not present."); // Logga se il versioning non è disponibile
        }

        // QUI CI FINISCE IL CODICE PER FUZZARE LE CREDENZIALI DEGLI UTENTI.


        return (internal_status, calls); // Ritorna lo stato e le chiamate
    } else {
        logga("Configuration record not available. Now quitting");
        return (NO_CONFIG_RCD, calls);
    }
}
