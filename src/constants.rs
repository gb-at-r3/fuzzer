// File: constants.rs
// Contains all the constants used throughout the project

// Generic statuses
pub const ALL_OK: u32 = 0;
pub const CLIENT_ERROR: u32 = 100;
pub const REQUEST_ERROR: u32 = 200;

// JSON-related errors
pub const NO_INPUT_FILE: u32 = 300;
pub const CANNOT_LOAD_JSON: u32 = 400;
pub const CANNOT_LOAD_JSON_PAYLOADS: u32 = 401;
pub const JSON_PARSING_ERROR: u32 = 410;
pub const JSON_PARSING_ERROR_PAYLOAD: u32 = 411;
pub const INVALID_JSON: u32 = 411; 
pub const NO_CONFIG_RCD: u32 = 500;

// Versioning-related errors
pub const MALFORMED_URI: u32 = 1000;
pub const MISSING_VERSION: u32 = 1001;
pub const MISSING_VER_VAR: u32 = 1002;
pub const TOO_MANY_VAR_VER: u32 = 1003;

// Testing constants
/// A placeholder parameter for testing purposes when no real value is available.
pub const DUMMY_PARAM: &str = "dummy_parameter";
