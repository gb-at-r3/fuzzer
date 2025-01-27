# fuzzer

## Current status
| **Attack Type**     | **No Encoding** | **URL Encoding** | **HTML Encoding** | **Base64** | **Base64 URL-Safe** | **Unicode Escaping** |
|----------------------|-----------------|------------------|-------------------|------------|---------------------|----------------------|
| **API9:2023**    | ✅              | ✅               | ✅                | ✅         | ✅                  | ✅                   |
| **API CREDENTIALS FUZZING**    | ✅              | ✅               | ✅                | ✅         | ✅                  | ✅                   |
| **SQL Injection**    | ✅              | ✅               | ✅                | ✅         | ✅                  | ✅                   |
| **NoSQL Injection**  | 🔲              | 🔲               | 🔲                | 🔲         | 🔲                  | 🔲                   |
| **OS Injection**     | 🔲              | 🔲               | 🔲                | 🔲         | 🔲                  | 🔲                   |
| **CRLF Injection**   | 🔲              | 🔲               | 🔲                | 🔲         | 🔲                  | 🔲                   |
| **Null Byte**        | 🔲              | 🔲               | 🔲                | 🔲         | 🔲                  | 🔲                   |
| **SSTI**             | 🔲              | 🔲               | 🔲                | 🔲         | 🔲                  | 🔲                   |
| **XPath Injection**  | 🔲              | 🔲               | 🔲                | 🔲         | 🔲                  | 🔲                   |
| **LDAP Injection**   | 🔲              | 🔲               | 🔲                | 🔲         | 🔲                  | 🔲                   |
