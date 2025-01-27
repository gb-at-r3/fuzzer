| **Test ID** | **Categoria**           | **Descrizione**                                                           | **Input Esempio**                                                     |
|-------------|-------------------------|---------------------------------------------------------------------------|------------------------------------------------------------------------|
| 1.1         | Autenticazione          | Credenziali valide                                                        | `API_key=key&API_secret=secret`                                       |
| 1.2         | Autenticazione          | Credenziali errate                                                        | `API_key=wrong_key&API_secret=wrong_secret`                           |
| 1.3         | Autenticazione          | Credenziali mancanti - manca API_secret                                   | `API_key=key`                                                         |
| 1.4         | Autenticazione          | Credenziali mancanti - manca API_key                                      | `API_secret=secret`                                                   |
| 1.5         | Autenticazione          | Credenziali vuote                                                          | `API_key=&API_secret=`                                                |
| 2.1         | Sicurezza               | Iniezione SQL - `OR 1=1`                                                   | `API_key=' OR 1=1 --&API_secret=' OR 1=1 --`                          |
| 2.2         | Sicurezza               | Iniezione di codice (XSS)                                                  | `API_key=<script>alert(1)</script>&API_secret=<script>alert(1)</script>` |
| 2.3         | Sicurezza               | Path Traversal                                                             | URL: `https://hostname.tld:port/../../etc/passwd`                     |
| 2.4.1       | Sicurezza (NoSQL)       | NoSQL Injection - Operatore `$where`                                      | `API_key={"$where": "this.API_key == 'key'"}&API_secret=secret`       |
| 2.4.2       | Sicurezza (NoSQL)       | NoSQL Injection - Operatore `$ne`                                         | `API_key={"$ne": null}&API_secret={"$ne": null}`                      |
| 2.4.3       | Sicurezza (NoSQL)       | NoSQL Injection - JavaScript embedded                                     | `API_key={"$where": "sleep(5000)"}&API_secret=secret`                 |
| 3.1         | Caratteri Strani        | Null Byte (`%00`)                                                          | `API_key=key%00&API_secret=secret`                                    |
| 3.2         | Caratteri Strani        | Newline (`%0A`)                                                            | `API_key=key%0AHeader:Injected&API_secret=secret`                      |
| 3.3         | Caratteri Strani        | Carriage Return (`%0D`)                                                    | `API_key=key%0D%0AInjected:Value&API_secret=secret`                    |
| 3.4         | Caratteri Strani        | Backslash (`%5C`)                                                          | `API_key=key%5Cadmin&API_secret=secret`                                |
| 3.5         | Caratteri Strani        | Percent Encoding (`%25`)                                                   | `API_key=%256Bey&API_secret=secret`                                    |
| 3.6         | Caratteri Strani        | Doppia Codifica (`%2527`)                                                  | `API_key=%2527admin%2527&API_secret=secret`                            |
| 3.7         | Caratteri Strani        | Unicode Null (`%u0000`)                                                    | `API_key=key%u0000&API_secret=secret`                                  |
| 3.8         | Caratteri Strani        | Unicode Special Characters                                                 | `API_key=𝒜𝒫𝒾_key&API_secret=𝓈𝑒𝒸𝓇𝑒𝓉`                                    |
| 3.9         | Caratteri Strani        | Entità HTML/XML (`<script>alert(1)</script>`)                              | `API_key=<script>alert(1)</script>&API_secret=secret`                  |
| 3.10        | Caratteri Strani        | Commento HTML (`<!-- -->`)                                                 | `API_key=<!-- key -->&API_secret=secret`                               |
