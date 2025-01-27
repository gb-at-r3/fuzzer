use serde::{Deserialize, Serialize};

// Livello principale
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct APIConfig {
    pub API_Nickname: String,
    pub API_Collection: String,
    pub API_structure: String,
    pub credentials: Credentials,
    pub variable_domains: Vec<VariableDomain>,
    pub API_KEY_VAR: VariableInfo,
    pub API_SECRET_VAR: VariableInfo,
    pub Payload: Vec<String>,
    pub auth_methods: Vec<String>,
    pub jwt_key: String,
    pub has_versioning: bool,
}

// Credenziali utente
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credentials {
    pub User: APICredentials,
    pub SuperUser: APICredentials,
    pub Hacker: APICredentials,
}

// Chiavi e segreti
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct APICredentials {
    pub API_key: String,
    pub API_secret: String,
}

impl APICredentials {
    pub fn flatten(&self) -> (String, String) {
        (self.API_key.clone(), self.API_secret.clone())
    }
}

// Variabili e domini
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VariableDomain {
    pub variable: String,
    pub domain: String,
}

// Informazioni API Key e Secret
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VariableInfo {
    pub varname: String,
    pub domain: String,
}
// ORIGINLA
// pub struct VariableInfo {
//     #[serde(rename = "var name")]
//     pub var_name: String,
//     pub domain: String,
// }


#[derive(Debug, Clone)]
pub enum TestType {
    Versioning,
    Fuzzing,
    SQLi,
    AuthBypass,
    Baselining,
    Generic,
    NotBetterDefined,
}

#[derive(Debug, Clone)]
pub struct HttpTestCase {
    pub actual_url: String,
    pub test_type: TestType,
    pub description: String,
    pub payload: Option<String>,
    pub auth_method: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Payload {
    pub id: Option<u32>,         // Opzionale, utile per catalogazione
    pub action: Taxonomy,        // Categoria tassonomica
    pub target: Vec<String>,     // Target RDBMS (es. MySQL, PostgreSQL, ecc.)
    pub tags: Option<Vec<String>>, // Tag aggiuntivi opzionali
    pub payload: String,         // Stringa della query o comando SQLi
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "value")]
pub enum Taxonomy {
    Detection(Detection),
    Enumeration(Enumeration),
    Exploitation(Exploitation),
    Destruction(Destruction),
    Evasion(Evasion),
    SideChannel(SideChannel),
    Misc(Misc),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Detection {
    TimeBased,
    BooleanBased,
    ErrorBased,
    UnionBased,
    StackedQueries,
    Blind,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Enumeration {
    Database,
    Tables,
    Columns,
    Users,
    Privileges,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Exploitation {
    DataExtraction,
    AuthenticationBypass,
    PrivilegeEscalation,
    SessionHijacking,
    CommandInjection,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Destruction {
    DropTable,
    TruncateTable,
    DeleteData,
    SchemaCorruption,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Evasion {
    Encoding,
    Obfuscation,
    CommentsInjection,
    DynamicSQL,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum SideChannel {
    TimingAttack,
    ErrorLeakage,
    TrafficAnalysis,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Misc {
    Probe,
    Test,
    Custom,
}
