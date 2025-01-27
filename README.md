# fuzzer

_This is still a development version_

## **Description**
Fuzzer is a tool designed to test APIs for vulnerabilities, specifically focusing on:
- **Versioning attacks** (API 2023:9)
- **SQL Injection** (API8:2019)
- **Credential fuzzing**

The tool generates a comprehensive set of test cases to evaluate the security of an API and outputs the URLs that can be used for further analysis or execution.

---

## **Features**
- Flexible and modular architecture for adding new attack types.
- Automatic handling of credentials and API structures.
- Customizable payloads for fuzzing.
- Multiple encoding techniques (e.g., Base64, URL encoding, HTML encoding).
- Command-line interface with verbosity control.

---

## **Prerequisites**
Before you can use the tool, ensure the following are installed:

1. **Rust**  
   Install Rust using [Rustup](https://rustup.rs/):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh




## Current status
| **Attack Type**     | **No Encoding** | **URL Encoding** | **HTML Encoding** | **Base64** | **Base64 URL-Safe** | **Unicode Escaping** |
|----------------------|-----------------|------------------|-------------------|------------|---------------------|----------------------|
| **API9:2023**    | ✅              | ➖               | ➖                | ➖         | ➖                  | ➖                   |
| **API CREDENTIALS FUZZING**    | ✅              | ➖               | ➖                | ➖         | ➖                  | ➖                   |
| **SQL Injection**    | ✅              | ✅               | ✅                | ✅         | ✅                  | ✅                   |
| **NoSQL Injection**  | 🔲              | 🔲               | 🔲                | 🔲         | 🔲                  | 🔲                   |
| **OS Injection**     | 🔲              | 🔲               | 🔲                | 🔲         | 🔲                  | 🔲                   |
| **CRLF Injection**   | 🔲              | 🔲               | 🔲                | 🔲         | 🔲                  | 🔲                   |
| **Null Byte**        | 🔲              | 🔲               | 🔲                | 🔲         | 🔲                  | 🔲                   |
| **SSTI**             | 🔲              | 🔲               | 🔲                | 🔲         | 🔲                  | 🔲                   |
| **XPath Injection**  | 🔲              | 🔲               | 🔲                | 🔲         | 🔲                  | 🔲                   |
| **LDAP Injection**   | 🔲              | 🔲               | 🔲                | 🔲         | 🔲                  | 🔲                   |



