# No Way, Jose!

A library to work with Javascript Object Signing and Encryption (JOSE), including:
* JSON Web Tokens (JWT)
* JSON Web Signature (JWS)
* JSON Web Encryption (JWE)
* JSON Web Algorithms (JWA)
* JSON Web Keys (JWK)

This was inspired by [`lawliet89/biscuit`](https://github.com/lawliet89/biscuit),
which is itself based off [`Keats/rust-jwt`](https://github.com/Keats/rust-jwt).

## Configuration

All cryptographic algorithms are chosen at compile time.
This reduces any risk of the infamous 'none' attack.

## Supported Features

The crate, does not support all, and probably will never support all of
the features described in the various RFCs, including some algorithms and verification.

## Quick Demo

### JWTs

```rust
use no_way::{JWT, jwa, jws, jwk, ClaimsSet, RegisteredClaims};
use serde::{Serialize, Deserialize};

// Define our own private claims
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct PrivateClaims {
    company: String,
    department: String,
}

let signing_key = jwk::OctetKey::new("secret".to_string().into_bytes());

let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
       eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1ZCI6Imh0dHBzOi8vYWNtZ\
       S1jdXN0b21lci5jb20vIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2\
       xlYW5pbmcifQ.VFCl2un1Kc17odzOe2Ehf4DVrWddu3U4Ux3GFpOZHtc";

let expected_claims = ClaimsSet::<PrivateClaims> {
    registered: RegisteredClaims {
        issuer: Some("https://www.acme.com/".into()),
        subject: Some("John Doe".to_string()),
        audience: Some("https://acme-customer.com/".into()),
        not_before: Some(1234.try_into().unwrap()),
        ..Default::default()
    },
    private: PrivateClaims {
        department: "Toilet Cleaning".to_string(),
        company: "ACME".to_string(),
    },
};

let jwt = JWT::new(expected_claims.clone());

let token = jwt.encode::<jwa::sign::HS256>(&signing_key).unwrap().to_string();
assert_eq!(expected_token, token);
// Now, send `token` to your clients

// ... some time later, we get token back!

let encoded_token: jws::Encoded<ClaimsSet::<PrivateClaims>> = token.parse().unwrap();
let token = JWT::<_>::decode::<jwa::sign::HS256>(encoded_token, &signing_key).unwrap();
assert_eq!(token.payload, expected_claims);
```

### JWEs

```rust
use no_way::{ClaimsSet, RegisteredClaims, JWT, JWE};
use no_way::jwk;
use no_way::jwe::Encrypted;
use no_way::jwa::{kma, cea, sign};
use serde::{Serialize, Deserialize};

// Define our own private claims
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct PrivateClaims {
    company: String,
    department: String,
}

// Craft our JWS
let expected_claims = ClaimsSet::<PrivateClaims> {
    registered: RegisteredClaims {
        issuer: Some("https://www.acme.com".into()),
        subject: Some("John Doe".into()),
        audience: Some("htts://acme-customer.com".into()),
        not_before: Some(1234.try_into().unwrap()),
        ..Default::default()
    },
    private: PrivateClaims {
        department: "Toilet Cleaning".to_string(),
        company: "ACME".to_string(),
    },
};

let expected_jwt = JWT::new(expected_claims.clone());

let signing_key = jwk::OctetKey::new("secret".to_string().into_bytes());
let jws = expected_jwt.encode::<sign::HS256>(&signing_key).unwrap();

// Encrypt the token

// You would usually have your own AES key for this, but we will use a zeroed key as an example
let key = jwk::OctetKey::new(vec![0; 256 / 8]);

/// We need to create a nonce for AES GCM encryption.
/// You must take care NOT to reuse the nonce.
/// You can simply treat the nonce as a 96 bit
/// counter that is incremented after every use
///
/// In this case, we're using a 64bit counter + a 32bit random prefix tag
fn generate_nonce() -> Vec<u8> {
    # use std::sync::atomic::{AtomicU64, Ordering};
    static NONCE: AtomicU64 = AtomicU64::new(0);
    // use some lazy random generation so each service has a separate tag
    static TAG: u32 = 0xDEADCAFE;

    // fetch and increment the nonce counter
    let nonce = NONCE.fetch_add(1, Ordering::Release);

    // collect the bytes together and return them
    let mut output = vec![0; 96/8];
    output[0..32/8].copy_from_slice(&TAG.to_be_bytes());
    output[32/8..].copy_from_slice(&nonce.to_be_bytes());
    output
}
let nonce = generate_nonce();

// Construct the JWE
let jwe = JWE::new(jws.clone());

// Encrypt
let encrypted_jwe = jwe.encrypt::<
    cea::A256GCM,   // encrypt the contents with AES256 GCM
    kma::A256GCMKW, // perform key wrapping with AES256 GCM
>(&key, nonce).unwrap();

let token = encrypted_jwe.to_string();

// Now, send `token` to your clients

// ... some time later, we get token back!
let token: Encrypted<kma::A256GCMKW> = token.parse().unwrap();

// Decrypt
let decrypted_jwe = token.decrypt::<_, cea::A256GCM>(&key).unwrap();

assert_eq!(jws, decrypted_jwe.payload);
```
