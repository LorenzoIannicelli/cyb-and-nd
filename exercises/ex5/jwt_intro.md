# Cybersecurity and National Defence Ex. 5
## A.Y. 2025/2026

### Contacts
* **Flavio Ciravegna:** [*flavio.ciravegna@polito.it*]
* **Silvia Sisinni:** [*silvia.sisinni@polito.it*]
* **Enrico Bravi:** [*enrico.bravi@polito.it*]
* **Lorenzo Ferro:** [*lorenzo.ferro@polito.it*]

---

## Overview

This laboratory focuses on JSON Web Tokens (JWTs). JWTs are widely used for authentication and information exchange between parties as a JSON object. This is particularly common in modern web applications and single sign-on (SSO) implementations. We will cover the concepts of JWT structure, stateless authentication, cryptographic signing algorithms (like HMAC), and common security vulnerabilities associated with JWT implementations.

### Prerequisites & Virtual Environments
Before executing the code, make sure you have created a Python virtual environment to isolate the project dependencies.

```bash
# Mac/Linux Environments
python3 -m venv myenv # skip if already created 
source myenv/bin/activate
pip install PyJWT cryptography jupyter nbformat requests

# Windows Environments
python -m venv myenv # skip if already created 
myenv\Scripts\activate
pip install PyJWT cryptography jupyter nbformat requests
```

---

## JSON Web Tokens (JWT)

### What is a JWT?
JSON Web Token (JWT) is an open standard ([RFC-7519](https://datatracker.ietf.org/doc/html/rfc7519)) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted since it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or an asymmetric key pair using RSA or ECDSA.

### Stateless Authentication
JWTs are extensively used in modern web applications for **stateless authentication**. 
When a user successfully logs in using their credentials, a JWT is returned. The server does not need to keep a record of the token (no session state) because the token itself contains all the information needed to identify the user and verify its validity. The client sends the token in the `Authorization` header using the `Bearer` schema:
`Authorization: Bearer <token>`

Since tokens are credentials, great care must be taken to prevent security issues. In general, you should not keep tokens longer than required.

### In brief
* **Compact:** JWTs are small and can be easily transmitted in URLs, query strings, HTTP headers, or body parameters.
* **Self-contained:** JWTs contain all the necessary information about the user, eliminating the need for the server to store session data.
* **Verifiable:** JWTs can be verified by the recipient to ensure their integrity and authenticity.

Additional information about JWT can be found in the [JWT official website](https://jwt.io/).

---

## JWT Structure

A JWT consists of three parts separated by dots (`.`):

`Header.Payload.Signature`

Since some characters used in JSON are not suitable for use in URLs and file names, the parts are encoded using **Base64Url encoding**.

### Header
The header typically consists of two parts: the type of the token, which is JWT, and the signing algorithm being used, such as HMAC-SHA256 (HS256), RSA, or ECDSA.
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
This JSON is Base64Url encoded to form the first part of the JWT.

### Payload
The second part of the token is the payload, which contains the **claims**. Claims are statements about a subject (typically, the user) and additional data.
There are three types of claims:
- **Registered claims:** Predefined claims which are not mandatory but recommended. These are:
   - `iss`: (issuer) issuer of the JWT
   - `sub`: (subject) subject of the JWT
   - `aud`: (audience) recipient for which the JWT is intended
   - `exp`: (expiration time) time after which the JWT is not valid
   - `iat`: (issued at) time at which the JWT was issued
   - `nbf`: (not before) time before which the JWT is not valid
   - `jti`: (JWT ID) unique identifier of the JWT
- **Public claims:** Defined at will by those using JWTs.
- **Private claims:** Custom claims created to share information between parties that agree on using them.
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```
This JSON is Base64Url encoded to form the second part of the JWT.
*Note: Anyone can decode the Base64Url payload to read its contents. Do not put secret information in the payload or header elements of a JWT unless it is encrypted.*

### Signature
To create the signature part you have to take the encoded header, the encoded payload, a secret, the algorithm specified in the header, and sign that.
For example, using the HMAC SHA256 algorithm, the signature is created this way:
```text
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```
The signature is used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way.


### Example

<span style="color:orange">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9</span>.<span style="color:green">eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ</span>.<span>SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c</span>

**Encoded Header:**
```json
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```
**Decoded Header:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
**Encoded Payload:**
```json
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
```
**Decoded Payload:**
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```
*Note: The payload is not encrypted, and anyone can decode the Base64Url payload to read its contents.*
      
**Signature:**
```text
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```
*Note: The signature is used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way.*

---

## JWT Security Considerations

### The "None" Algorithm Vulnerability
The JWT specification allows the `alg` header to be set to `none`. This indicates that the token is not signed. If a server is misconfigured to accept `none` as a valid algorithm, an attacker can modify the payload (e.g., change `"admin": false` to `"admin": true`), strip the signature, set `alg: none`, and the server will accept it as valid. Modern libraries mitigate this by requiring the algorithm to be explicitly specified during verification.

### Weak HMAC Secrets
When using HMAC (like HS256), the security of the signature relies entirely on the strength of the secret key. If the key is weak or predictable (e.g., "secret", "password", or common words), an attacker can perform a brute-force or dictionary attack offline to discover the secret. Once the secret is known, the attacker can forge valid tokens for any user.

### Token Expiration
Tokens should always have a reasonable expiration time (`exp` claim) to limit the window of opportunity if a token is stolen.

---