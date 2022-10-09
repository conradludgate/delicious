//! # No Way, Jose!
//!
//! A library to work with Javascript Object Signing and Encryption (JOSE), including:
//! * JSON Web Tokens (JWT)
//! * JSON Web Signature (JWS)
//! * JSON Web Encryption (JWE)
//! * JSON Web Algorithms (JWA)
//! * JSON Web Keys (JWK)
//!
//! # Examples
//!
//! ## Sign a token with HS256, then encrypt with A256GCMKW and A256GCM
//!
//! ```rust
//! use no_way::{ClaimsSet, RegisteredClaims, JWT, JWE};
//! use no_way::jwk;
//! use no_way::jwe::Encrypted;
//! use no_way::jwa::{kma, cea, sign};
//! use serde::{Serialize, Deserialize};
//!
//! // Define our own private claims
//! #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
//! struct PrivateClaims {
//!     company: String,
//!     department: String,
//! }
//!
//! let signing_key = jwk::OctetKey::new("secret".to_string().into_bytes());
//!
//! let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
//!        eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1ZCI6Imh0dHBzOi8vYWNtZ\
//!        S1jdXN0b21lci5jb20vIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2\
//!        xlYW5pbmcifQ.VFCl2un1Kc17odzOe2Ehf4DVrWddu3U4Ux3GFpOZHtc";
//!
//! let expected_claims = ClaimsSet::<PrivateClaims> {
//!     registered: RegisteredClaims {
//!         issuer: Some("https://www.acme.com/".into()),
//!         subject: Some("John Doe".to_string()),
//!         audience: Some("https://acme-customer.com/".into()),
//!         not_before: Some(1234.try_into().unwrap()),
//!         ..Default::default()
//!     },
//!     private: PrivateClaims {
//!         department: "Toilet Cleaning".to_string(),
//!         company: "ACME".to_string(),
//!     },
//! };
//!
//! let jwt = JWT::new(expected_claims.clone());
//!
//! let jws_token = jwt.encode::<sign::HS256>(&signing_key).unwrap();
//! assert_eq!(expected_token, jws_token.to_string());
//!
//! // Encrypt the token
//!
//! // You would usually have your own AES key for this, but we will use a zeroed key as an example
//! let key = jwk::OctetKey::new(vec![0; 256 / 8]);
//!
//! /// We need to create a nonce for AES GCM encryption.
//! /// You must take care NOT to reuse the nonce.
//! /// You can simply treat the nonce as a 96 bit
//! /// counter that is incremented after every use
//! ///
//! /// In this case, we're using a 64bit counter + a 32bit random prefix tag
//! fn generate_nonce() -> [u8; 96/8] {
//!     # use std::sync::atomic::{AtomicU64, Ordering};
//!     static NONCE: AtomicU64 = AtomicU64::new(0);
//!     // use some lazy random generation so each service has a separate tag
//!     static TAG: u32 = 0xDEADCAFE;
//!
//!     // fetch and increment the nonce counter
//!     let nonce = NONCE.fetch_add(1, Ordering::Release);
//!
//!     // collect the bytes together and return them
//!     let mut output = [0; 96/8];
//!     output[0..32/8].copy_from_slice(&TAG.to_be_bytes());
//!     output[32/8..].copy_from_slice(&nonce.to_be_bytes());
//!     output
//! }
//! let nonce = generate_nonce();
//!
//! // Construct the JWE
//! let jwe = JWE::new(jws_token.clone());
//!
//! // Encrypt
//! let encrypted_jwe = jwe.encrypt::<
//!     cea::A256GCM,   // encrypt the contents with AES256 GCM
//!     kma::A256GCMKW, // perform key wrapping with AES256 GCM
//! >(&key, nonce).unwrap();
//!
//! let jwe_token = encrypted_jwe.to_string();
//!
//! // Now, send `token` to your clients
//!
//! // ... some time later, we get token back!
//! let encrypted_jwe: Encrypted<kma::A256GCMKW> = jwe_token.parse().unwrap();
//!
//! // Decrypt
//! let decrypted_jwe: JWE<_> = encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
//!
//! // Verify the JWT signature
//! let decoded_jwt = decrypted_jwe.payload.verify::<sign::HS256>(&signing_key).unwrap();
//!
//! assert_eq!(decoded_jwt.payload, expected_claims);
//! ```

// ### RFCs
// - [JSON Web Tokens RFC](https://tools.ietf.org/html/rfc7519)
// - [JSON Web Signature RFC](https://tools.ietf.org/html/rfc7515)
// - [JSON Web Algorithms RFC](https://tools.ietf.org/html/rfc7518)
// - [JSON Web Encryption RFC](https://tools.ietf.org/html/rfc7516)
// - [JSON Web Signature (JWS) Unencoded Payload Option](https://tools.ietf.org/html/rfc7797)
// - [CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE](https://tools.ietf.org/html/rfc8037)
// - [JWS Unencoded Payload Option](https://tools.ietf.org/html/rfc7797)
// - [JWK Thumbprint](https://tools.ietf.org/html/rfc7638)

#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::default_trait_access,
    clippy::similar_names,
    clippy::enum_glob_use
)]

use std::borrow::Cow;
use std::fmt::Debug;
use std::ops::Deref;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::{Duration, OffsetDateTime};

mod helpers;
pub use crate::helpers::*;

#[cfg(test)]
#[macro_use]
mod test;

#[macro_use]
mod serde_custom;

#[macro_use]
mod macros;

pub mod errors;
pub mod jwa;
pub mod jwe;
pub mod jwk;
pub mod jws;

use crate::errors::{Error, ValidationError};

/// A trait to describe how to parse components of a compact form JWS or JWE
pub trait FromCompactPart: Sized {
    /// Try and parse raw bytes into Self
    fn from_bytes(b: &[u8]) -> Result<Self, Error>;
}

/// A trait to describe how to produce components of a compact form JWS or JWE
pub trait ToCompactPart: Sized {
    /// Convert self into raw bytes
    fn to_bytes(&self) -> Result<Cow<'_, [u8]>, Error>;
}

/// A [`CompactPart`] type that parses data as json using [`serde_json`]
pub struct Json<T>(pub T);

impl<T: DeserializeOwned> FromCompactPart for Json<T> {
    fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(Json(serde_json::from_slice(b)?))
    }
}
impl<T: Serialize> ToCompactPart for Json<T> {
    fn to_bytes(&self) -> Result<Cow<'_, [u8]>, Error> {
        Ok(serde_json::to_vec(&self.0)?.into())
    }
}

impl FromCompactPart for Vec<u8> {
    fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(b.to_vec())
    }
}
impl ToCompactPart for Vec<u8> {
    fn to_bytes(&self) -> Result<Cow<'_, [u8]>, Error> {
        Ok(self.as_slice().into())
    }
}

impl FromCompactPart for () {
    fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.is_empty() {
            Ok(())
        } else {
            Err(Error::DecodeError(errors::DecodeError::PartsLengthError {
                expected: 0,
                actual: b.len(),
            }))
        }
    }
}
impl ToCompactPart for () {
    fn to_bytes(&self) -> Result<Cow<'_, [u8]>, Error> {
        Ok(Cow::Borrowed(&[]))
    }
}

/// A convenience type alias of a JSON Web Encryption token in it's decoded form. It
/// contains a [`ClaimsSet`] as it's contents
///
/// Type `T` is the type of private claims for the JWT.
///
/// # Examples
/// ## Encoding and decoding with HS256
///
/// ```
/// use no_way::{JWT, jwa, jws, jwk, ClaimsSet, RegisteredClaims};
/// use serde::{Serialize, Deserialize};
///
/// // Define our own private claims
/// #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
/// struct PrivateClaims {
///     company: String,
///     department: String,
/// }
///
/// let signing_key = jwk::OctetKey::new("secret".to_string().into_bytes());
///
/// let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
///        eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1ZCI6Imh0dHBzOi8vYWNtZ\
///        S1jdXN0b21lci5jb20vIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2\
///        xlYW5pbmcifQ.VFCl2un1Kc17odzOe2Ehf4DVrWddu3U4Ux3GFpOZHtc";
///
/// let expected_claims = ClaimsSet::<PrivateClaims> {
///     registered: RegisteredClaims {
///         issuer: Some("https://www.acme.com/".into()),
///         subject: Some("John Doe".to_string()),
///         audience: Some("https://acme-customer.com/".into()),
///         not_before: Some(1234.try_into().unwrap()),
///         ..Default::default()
///     },
///     private: PrivateClaims {
///         department: "Toilet Cleaning".to_string(),
///         company: "ACME".to_string(),
///     },
/// };
///
/// let jwt = JWT::new(expected_claims.clone());
///
/// let token = jwt.encode::<jwa::sign::HS256>(&signing_key).unwrap().to_string();
/// assert_eq!(expected_token, token);
/// // Now, send `token` to your clients
///
/// // ... some time later, we get token back!
///
/// let encoded_token: jws::Unverified<_> = token.parse().unwrap();
/// let token: JWT<_> = encoded_token.verify::<jwa::sign::HS256>(&signing_key).unwrap();
/// assert_eq!(token.payload, expected_claims);
/// ```
pub type JWT<T> = jws::Verified<ClaimsSet<T>, ()>;

/// A convenience type alias of a JSON Web Encryption token in it's decrypted form. It contains
/// an encoded JWT<T> as it's contents.
///
/// Type `T` is the type of private claims for the JWT.
///
/// # Examples
/// ## Sign with HS256, then encrypt with A256GCMKW and A256GCM
///
/// ```rust
/// use no_way::{ClaimsSet, RegisteredClaims, JWT, JWE};
/// use no_way::jwk;
/// use no_way::jwe::Encrypted;
/// use no_way::jwa::{kma, cea, sign};
/// use serde::{Serialize, Deserialize};
///
/// // Define our own private claims
/// #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
/// struct PrivateClaims {
///     company: String,
///     department: String,
/// }
///
/// // Craft our JWS
/// let expected_claims = ClaimsSet::<PrivateClaims> {
///     registered: RegisteredClaims {
///         issuer: Some("https://www.acme.com".into()),
///         subject: Some("John Doe".into()),
///         audience: Some("htts://acme-customer.com".into()),
///         not_before: Some(1234.try_into().unwrap()),
///         ..Default::default()
///     },
///     private: PrivateClaims {
///         department: "Toilet Cleaning".to_string(),
///         company: "ACME".to_string(),
///     },
/// };
///
/// let expected_jwt = JWT::new(expected_claims.clone());
///
/// let signing_key = jwk::OctetKey::new("secret".to_string().into_bytes());
/// let jws = expected_jwt.encode::<sign::HS256>(&signing_key).unwrap();
///
/// // Encrypt the token
///
/// // You would usually have your own AES key for this, but we will use a zeroed key as an example
/// let key = jwk::OctetKey::new(vec![0; 256 / 8]);
///
/// /// We need to create a nonce for AES GCM encryption.
/// /// You must take care NOT to reuse the nonce.
/// /// You can simply treat the nonce as a 96 bit
/// /// counter that is incremented after every use
/// ///
/// /// In this case, we're using a 64bit counter + a 32bit random prefix tag
/// fn generate_nonce() -> [u8; 96/8] {
///     # use std::sync::atomic::{AtomicU64, Ordering};
///     static NONCE: AtomicU64 = AtomicU64::new(0);
///     // use some lazy random generation so each service has a separate tag
///     static TAG: u32 = 0xDEADCAFE;
///
///     // fetch and increment the nonce counter
///     let nonce = NONCE.fetch_add(1, Ordering::Release);
///
///     // collect the bytes together and return them
///     let mut output = [0; 96/8];
///     output[0..32/8].copy_from_slice(&TAG.to_be_bytes());
///     output[32/8..].copy_from_slice(&nonce.to_be_bytes());
///     output
/// }
/// let nonce = generate_nonce();
///
/// // Construct the JWE
/// let jwe = JWE::new(jws.clone());
///
/// // Encrypt
/// let encrypted_jwe = jwe.encrypt::<
///     cea::A256GCM,   // encrypt the contents with AES256 GCM
///     kma::A256GCMKW, // perform key wrapping with AES256 GCM
/// >(&key, nonce).unwrap();
///
/// let token = encrypted_jwe.to_string();
///
/// // Now, send `token` to your clients
///
/// // ... some time later, we get token back!
/// let token: Encrypted<kma::A256GCMKW> = token.parse().unwrap();
///
/// // Decrypt
/// let decrypted_jwe = token.decrypt::<_, cea::A256GCM>(&key).unwrap();
///
/// assert_eq!(jws, decrypted_jwe.payload);
/// ```
pub type JWE<T> = jwe::Decrypted<jws::Unverified<ClaimsSet<T>>, ()>;

/// Represents a choice between a single value or multiple string values.
///
/// # Examples
/// ```
/// # use no_way::SingleOrMultiple;
/// let single: SingleOrMultiple = "foobar".into();
/// let expected_json = r#""foobar""#;
///
/// let serialized = serde_json::to_string(&single).unwrap();
/// assert_eq!(expected_json, serialized);
///
/// let deserialized: SingleOrMultiple = serde_json::from_str(&serialized).unwrap();
/// assert_eq!(deserialized, single);
///
/// let multiple: SingleOrMultiple = ["foo", "bar", "baz"].as_slice().into();
/// let expected_json = r#"["foo","bar","baz"]"#;
///
/// let serialized = serde_json::to_string(&multiple).unwrap();
/// assert_eq!(expected_json, serialized);
///
/// let deserialized: SingleOrMultiple = serde_json::from_str(&serialized).unwrap();
/// assert_eq!(deserialized, multiple);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SingleOrMultiple {
    /// One single value
    Single([String; 1]),
    /// Multiple values
    Multiple(Vec<String>),
}

mod serde_impls {
    use super::SingleOrMultiple;

    impl serde::Serialize for SingleOrMultiple {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match self {
                SingleOrMultiple::Single([field]) => field.serialize(serializer),
                SingleOrMultiple::Multiple(ref field) => field.serialize(serializer),
            }
        }
    }

    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = SingleOrMultiple;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("single or multiple strings")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v.into())
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v.into())
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = seq.next_element()? {
                values.push(value);
            }
            Ok(SingleOrMultiple::Multiple(values))
        }
    }
    impl<'de> serde::Deserialize<'de> for SingleOrMultiple {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(Visitor)
        }
    }
}

impl From<&str> for SingleOrMultiple {
    fn from(t: &str) -> Self {
        Self::Single([t.to_owned()])
    }
}
impl From<&[&str]> for SingleOrMultiple {
    fn from(t: &[&str]) -> Self {
        Self::Multiple(t.iter().map(|&s| s.to_owned()).collect())
    }
}
impl From<String> for SingleOrMultiple {
    fn from(t: String) -> Self {
        Self::Single([t])
    }
}
impl From<Vec<String>> for SingleOrMultiple {
    fn from(t: Vec<String>) -> Self {
        Self::Multiple(t)
    }
}

impl SingleOrMultiple {
    /// Checks whether this enum, regardless of single or multiple value contains `value`.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Self::Single([single]) => single == value,
            Self::Multiple(vector) => vector.iter().any(|v| v == value),
        }
    }

    /// Yields an iterator for the single value or the list
    pub fn iter(&self) -> std::slice::Iter<String> {
        match self {
            Self::Single(single) => single.iter(),
            Self::Multiple(vector) => vector.iter(),
        }
    }
}

/// Wrapper around `OffsetDateTime` to allow us to do custom de(serialization)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp(OffsetDateTime);

impl Deref for Timestamp {
    type Target = OffsetDateTime;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<OffsetDateTime> for Timestamp {
    fn from(datetime: OffsetDateTime) -> Self {
        Timestamp(datetime)
    }
}

impl From<Timestamp> for OffsetDateTime {
    fn from(ts: Timestamp) -> Self {
        ts.0
    }
}

impl TryFrom<i64> for Timestamp {
    type Error = time::error::ComponentRange;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        OffsetDateTime::from_unix_timestamp(value).map(Self)
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        time::serde::timestamp::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        time::serde::timestamp::deserialize(deserializer).map(Self)
    }
}

/// Registered claims defined by [RFC7519#4.1](https://tools.ietf.org/html/rfc7519#section-4.1)
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct RegisteredClaims {
    /// Token issuer. Serialized to `iss`.
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// Subject where the JWT is referring to. Serialized to `sub`
    #[serde(rename = "sub", skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    /// Audience intended for the JWT. Serialized to `aud`
    #[serde(rename = "aud", skip_serializing_if = "Option::is_none")]
    pub audience: Option<SingleOrMultiple>,

    /// Expiration time in seconds since Unix Epoch. Serialized to `exp`
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    pub expiry: Option<Timestamp>,

    /// Not before time in seconds since Unix Epoch. Serialized to `nbf`
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<Timestamp>,

    /// Issued at Time in seconds since Unix Epoch. Serialized to `iat`
    #[serde(rename = "iat", skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<Timestamp>,

    /// Application specific JWT ID. Serialized to `jti`
    #[serde(rename = "jti", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Default)]
/// Options for claims presence validation
///
/// By default, no claims (namely `iat`, `exp`, `nbf`, `iss`, `aud`)
/// are required, and they pass validation if they are missing.
pub struct ClaimPresenceOptions {
    /// Whether the `iat` or `Issued At` field is required
    pub issued_at: Presence,
    /// Whether the `nbf` or `Not Before` field is required
    pub not_before: Presence,
    /// Whether the `exp` or `Expiry` field is required
    pub expiry: Presence,
    /// Whether the `iss` or `Issuer` field is required
    pub issuer: Presence,
    /// Whether the `aud` or `Audience` field is required
    pub audience: Presence,
    /// Whether the `sub` or `Subject` field is required
    pub subject: Presence,
    /// Whether the `jti` or `JWT ID` field is required
    pub id: Presence,
}

impl ClaimPresenceOptions {
    /// Returns a `ClaimPresenceOptions` where every claim is required as per [RFC7523](https://tools.ietf.org/html/rfc7523#section-3)
    pub fn strict() -> Self {
        use Presence::Required;
        ClaimPresenceOptions {
            issued_at: Required,
            not_before: Required,
            expiry: Required,
            issuer: Required,
            audience: Required,
            subject: Required,
            id: Required,
        }
    }
}

#[derive(Eq, PartialEq, Clone)]
/// Options for claims validation
///
/// If a claim is missing, it passes validation unless the claim is marked as required within the
/// `claim_presence_options`.
///
/// By default, no claims are required. If there are present, only expiry-related claims are validated
/// (namely `exp`, `nbf`, `iat`) with zero epsilon and maximum age duration.
///
/// Should any temporal claims be required, set the appropriate fields.
///
/// To deal with clock drifts, you might want to provide an `epsilon` error margin in the form of a
/// `std::time::Duration` to allow time comparisons to fall within the margin.
pub struct ValidationOptions {
    /// Claims marked as required will trigger a validation failure if they are missing
    pub claim_presence_options: ClaimPresenceOptions,

    /// Define how to validate temporal claims
    pub temporal_options: TemporalOptions,

    /// Validation options for `iat` or `Issued At` claim if present
    /// Parameter shows the maximum age of a token to be accepted,
    /// use [```Duration::max_value()```] if you do not want to skip validating
    /// the age of the token, and only validate it was not issued in the future
    pub issued_at: Validation<Duration>,
    /// Validation options for `nbf` or `Not Before` claim if present
    pub not_before: Validation<()>,
    /// Validation options for `exp` or `Expiry` claim if present
    pub expiry: Validation<()>,

    /// Validation options for `iss` or `Issuer` claim if present
    /// Parameter must match the issuer in the token exactly.
    pub issuer: Validation<String>,

    /// Validation options for `aud` or `Audience` claim if present
    /// Token must include an audience with the value of the parameter
    pub audience: Validation<String>,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        ValidationOptions {
            expiry: Validation::Validate(()),
            not_before: Validation::Validate(()),
            issued_at: Validation::Validate(Duration::MAX),

            claim_presence_options: Default::default(),
            temporal_options: Default::default(),
            audience: Default::default(),
            issuer: Default::default(),
        }
    }
}

impl RegisteredClaims {
    /// Validates that the token contains the claims defined as required
    pub fn validate_claim_presence(
        &self,
        options: ClaimPresenceOptions,
    ) -> Result<(), ValidationError> {
        use crate::Presence::Required;

        let mut missing_claims: Vec<&str> = vec![];

        if options.expiry == Required && self.expiry.is_none() {
            missing_claims.push("exp");
        }

        if options.not_before == Required && self.not_before.is_none() {
            missing_claims.push("nbf");
        }

        if options.issued_at == Required && self.issued_at.is_none() {
            missing_claims.push("iat");
        }

        if options.audience == Required && self.audience.is_none() {
            missing_claims.push("aud");
        }

        if options.issuer == Required && self.issuer.is_none() {
            missing_claims.push("iss");
        }

        if options.subject == Required && self.subject.is_none() {
            missing_claims.push("sub");
        }

        if options.id == Required && self.id.is_none() {
            missing_claims.push("jti");
        }

        if missing_claims.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::MissingRequiredClaims(
                missing_claims.into_iter().map(Into::into).collect(),
            ))
        }
    }

    /// Validates that if the token has an `exp` claim, it has not passed.
    pub fn validate_exp(
        &self,
        validation: Validation<TemporalOptions>,
    ) -> Result<(), ValidationError> {
        match validation {
            Validation::Ignored => Ok(()),
            Validation::Validate(temporal_options) => {
                let now = temporal_options.now.unwrap_or_else(OffsetDateTime::now_utc);

                match self.expiry {
                    Some(Timestamp(expiry)) if now - expiry > temporal_options.epsilon => {
                        Err(ValidationError::Expired(now - expiry))
                    }
                    _ => Ok(()),
                }
            }
        }
    }

    /// Validates that if the token has an `nbf` claim, it has passed.
    pub fn validate_nbf(
        &self,
        validation: Validation<TemporalOptions>,
    ) -> Result<(), ValidationError> {
        match validation {
            Validation::Ignored => Ok(()),
            Validation::Validate(temporal_options) => {
                let now = temporal_options.now.unwrap_or_else(OffsetDateTime::now_utc);

                match self.not_before {
                    Some(Timestamp(nbf)) if nbf - now > temporal_options.epsilon => {
                        Err(ValidationError::NotYetValid(nbf - now))
                    }
                    _ => Ok(()),
                }
            }
        }
    }

    /// Validates that if the token has an `iat` claim, it is not in the future and not older than the Duration
    pub fn validate_iat(
        &self,
        validation: Validation<(Duration, TemporalOptions)>,
    ) -> Result<(), ValidationError> {
        match validation {
            Validation::Ignored => Ok(()),
            Validation::Validate((max_age, temporal_options)) => {
                let now = temporal_options.now.unwrap_or_else(OffsetDateTime::now_utc);

                match self.issued_at {
                    Some(Timestamp(iat)) if iat - now > temporal_options.epsilon => {
                        Err(ValidationError::NotYetValid(iat - now))
                    }
                    Some(Timestamp(iat)) if now - iat > max_age - temporal_options.epsilon => {
                        Err(ValidationError::TooOld(now - iat - max_age))
                    }
                    _ => Ok(()),
                }
            }
        }
    }

    /// Validates that if the token has an `aud` claim, it contains an entry which matches the expected audience
    pub fn validate_aud(&self, validation: Validation<String>) -> Result<(), ValidationError> {
        match validation {
            Validation::Ignored => Ok(()),
            Validation::Validate(expected_aud) => match &self.audience {
                Some(SingleOrMultiple::Single([audience])) if audience != &expected_aud => Err(
                    ValidationError::InvalidAudience(SingleOrMultiple::Single([audience.clone()])),
                ),
                Some(SingleOrMultiple::Multiple(audiences))
                    if !audiences.contains(&expected_aud) =>
                {
                    Err(ValidationError::InvalidAudience(
                        SingleOrMultiple::Multiple(audiences.clone()),
                    ))
                }
                _ => Ok(()),
            },
        }
    }

    /// Validates that if the token has an `iss` claim, it matches the expected issuer
    pub fn validate_iss(&self, validation: Validation<String>) -> Result<(), ValidationError> {
        match validation {
            Validation::Ignored => Ok(()),
            Validation::Validate(expected_issuer) => match self.issuer {
                Some(ref iss) if iss != &expected_issuer => {
                    Err(ValidationError::InvalidIssuer(iss.clone()))
                }
                _ => Ok(()),
            },
        }
    }

    /// Performs full validation of the token according to the `ValidationOptions` supplied
    ///
    /// First it validates that all claims marked as required are present
    /// Then it validates each claim marked to be validated if they are present in the token
    /// (even those that are not marked as required, but are present).
    pub fn validate(&self, options: ValidationOptions) -> Result<(), ValidationError> {
        self.validate_claim_presence(options.claim_presence_options)?;
        self.validate_exp(options.expiry.map(|_| options.temporal_options))?;
        self.validate_nbf(options.not_before.map(|_| options.temporal_options))?;
        self.validate_iat(options.issued_at.map(|dur| (dur, options.temporal_options)))?;

        self.validate_iss(options.issuer)?;
        self.validate_aud(options.audience)?;

        //        self.validate_sub(options.subject_validated)?;
        //        self.validate_custom(options.custom_validation)?;

        Ok(())
    }
}

/// A collection of claims, both [registered](https://tools.ietf.org/html/rfc7519#section-4.1) and your custom
/// private claims.
#[derive(Debug, Eq, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct ClaimsSet<T> {
    /// Registered claims defined by the RFC
    #[serde(flatten)]
    pub registered: RegisteredClaims,
    /// Application specific claims
    #[serde(flatten)]
    pub private: T,
}

impl<T: DeserializeOwned> FromCompactPart for ClaimsSet<T> {
    fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(serde_json::from_slice(b)?)
    }
}
impl<T: Serialize> ToCompactPart for ClaimsSet<T> {
    fn to_bytes(&self) -> Result<Cow<'_, [u8]>, Error> {
        Ok(serde_json::to_vec(&self)?.into())
    }
}

type B64 = base64ct::Base64UrlUnpadded;

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct PrivateClaims {
        company: String,
        department: String,
    }

    // impl CompactJson for PrivateClaims {}

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct InvalidPrivateClaim {
        sub: String,
        company: String,
    }

    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct SingleOrMultipleStrings {
        values: SingleOrMultiple,
    }

    #[test]
    fn single_string_serialization_round_trip() {
        let test = SingleOrMultipleStrings {
            values: "foobar".into(),
        };
        let expected_json = r#"{"values":"foobar"}"#;

        let serialized = serde_json::to_string(&test).unwrap();
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStrings = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, test);
        assert!(deserialized.values.contains("foobar"));
        assert!(!deserialized.values.contains("does not exist"));
    }

    #[test]
    fn multiple_strings_serialization_round_trip() {
        let test = SingleOrMultipleStrings {
            values: ["foo", "bar", "baz"].as_slice().into(),
        };
        let expected_json = r#"{"values":["foo","bar","baz"]}"#;

        let serialized = serde_json::to_string(&test).unwrap();
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStrings = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, test);
        assert!(deserialized.values.contains("foo"));
        assert!(deserialized.values.contains("bar"));
        assert!(deserialized.values.contains("baz"));
        assert!(!deserialized.values.contains("does not exist"));
    }

    #[test]
    fn single_string_or_uri_string_serialization_round_trip() {
        let test = SingleOrMultipleStrings {
            values: "foobar".into(),
        };
        let expected_json = r#"{"values":"foobar"}"#;

        let serialized = serde_json::to_string(&test).unwrap();
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStrings = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, test);
        assert!(deserialized.values.contains("foobar"));
        assert!(!deserialized.values.contains("does not exist"));
    }

    #[test]
    fn single_string_or_uri_uri_serialization_round_trip() {
        let test = SingleOrMultipleStrings {
            values: "https://www.examples.com/".into(),
        };
        let expected_json = r#"{"values":"https://www.examples.com/"}"#;

        let serialized = serde_json::to_string(&test).unwrap();
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStrings = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, test);
        assert!(deserialized.values.contains("https://www.examples.com/"));
        assert!(!deserialized.values.contains("https://ecorp.com"));
    }

    #[test]
    fn multiple_string_or_uri_serialization_round_trip() {
        let test = SingleOrMultipleStrings {
            values: [
                "foo",
                "https://www.example.com/",
                "data:text/plain,Hello?World#",
                "http://[::1]/",
                "baz",
            ]
            .as_slice()
            .into(),
        };
        let expected_json = r#"{"values":["foo","https://www.example.com/","data:text/plain,Hello?World#","http://[::1]/","baz"]}"#;

        let serialized = serde_json::to_string(&test).unwrap();
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStrings = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, test);

        assert!(deserialized.values.contains("foo"));
        assert!(deserialized.values.contains("https://www.example.com/"));
        assert!(deserialized.values.contains("data:text/plain,Hello?World#"));
        assert!(deserialized.values.contains("http://[::1]/"));
        assert!(deserialized.values.contains("baz"));
        assert!(!deserialized.values.contains("https://ecorp.com"));
    }

    #[test]
    fn timestamp_serialization_roundtrip() {
        let now: Timestamp = OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .unwrap()
            .into();
        let serialized = serde_json::to_string(&now).unwrap();
        let deserialized = serde_json::from_str(&serialized).unwrap();
        assert_eq!(now, deserialized);

        let fixed_time: Timestamp = 1000.try_into().unwrap();
        let serialized = serde_json::to_string(&fixed_time).unwrap();
        assert_eq!(serialized, "1000");
        let deserialized = serde_json::from_str(&serialized).unwrap();
        assert_eq!(fixed_time, deserialized);
    }

    #[test]
    fn empty_registered_claims_serialization_round_trip() {
        let claim = RegisteredClaims::default();
        let expected_json = "{}";

        let serialized = serde_json::to_string(&claim).unwrap();
        assert_eq!(expected_json, serialized);

        let deserialized: RegisteredClaims = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, claim);
    }

    #[test]
    fn registered_claims_serialization_round_trip() {
        let claim = RegisteredClaims {
            issuer: Some("https://www.acme.com/".into()),
            audience: Some("htts://acme-customer.com/".into()),
            not_before: Some(1234.try_into().unwrap()),
            ..Default::default()
        };
        let expected_json =
            r#"{"iss":"https://www.acme.com/","aud":"htts://acme-customer.com/","nbf":1234}"#;

        let serialized = serde_json::to_string(&claim).unwrap();
        assert_eq!(expected_json, serialized);

        let deserialized: RegisteredClaims = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, claim);
    }

    #[test]
    fn claims_set_serialization_round_trip() {
        let claim = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some("https://www.acme.com/".into()),
                subject: Some("John Doe".into()),
                audience: Some("htts://acme-customer.com/".into()),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let expected_json = "{\"iss\":\"https://www.acme.com/\",\"sub\":\"John Doe\",\
                             \"aud\":\"htts://acme-customer.com/\",\
                             \"nbf\":1234,\"company\":\"ACME\",\"department\":\"Toilet Cleaning\"}";

        let serialized = serde_json::to_string(&claim).unwrap();
        assert_eq!(expected_json, serialized);

        let deserialized: ClaimsSet<PrivateClaims> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, claim);
    }

    #[test]
    // serde's flatten will serialize them twice
    fn duplicate_claims_round_trip() {
        let claim = ClaimsSet::<InvalidPrivateClaim> {
            registered: RegisteredClaims {
                issuer: Some("https://www.acme.com".into()),
                subject: Some("John Doe".into()),
                audience: Some("htts://acme-customer.com".into()),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: InvalidPrivateClaim {
                sub: "John Doe".to_string(),
                company: "ACME".to_string(),
            },
        };

        let json = serde_json::to_string(&claim).unwrap();
        assert_eq!(2, json.matches("\"sub\"").count());

        let duplicate: Result<ClaimsSet<InvalidPrivateClaim>, _> = serde_json::from_str(&json);
        assert!(duplicate.is_err());
        let error = duplicate.unwrap_err().to_string();
        assert!(error.contains("duplicate field `sub`"));
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"iat\"])")]
    fn validate_times_missing_iat() {
        let registered_claims = RegisteredClaims::default();
        let options = ClaimPresenceOptions {
            issued_at: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"exp\"])")]
    fn validate_times_missing_exp() {
        let registered_claims = RegisteredClaims::default();
        let options = ClaimPresenceOptions {
            expiry: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"nbf\"])")]
    fn validate_times_missing_nbf() {
        let registered_claims = RegisteredClaims::default();
        let options = ClaimPresenceOptions {
            not_before: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"aud\"])")]
    fn validate_times_missing_aud() {
        let registered_claims = RegisteredClaims::default();
        let options = ClaimPresenceOptions {
            audience: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"iss\"])")]
    fn validate_times_missing_iss() {
        let registered_claims = RegisteredClaims::default();
        let options = ClaimPresenceOptions {
            issuer: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"sub\"])")]
    fn validate_times_missing_sub() {
        let registered_claims = RegisteredClaims::default();
        let options = ClaimPresenceOptions {
            subject: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(
        expected = "MissingRequiredClaims([\"exp\", \"nbf\", \"iat\", \"aud\", \"iss\", \"sub\", \"jti\"])"
    )]
    fn validate_times_missing_all() {
        let registered_claims = RegisteredClaims::default();
        let options = ClaimPresenceOptions::strict();
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    fn validate_times_catch_future_token() {
        let temporal_options = TemporalOptions {
            now: Some(OffsetDateTime::from_unix_timestamp(0).unwrap()),
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            issued_at: Some(10.try_into().unwrap()),
            ..Default::default()
        };

        assert_eq!(
            Err(ValidationError::NotYetValid(Duration::seconds(10))),
            registered_claims.validate_iat(Validation::Validate((
                Duration::seconds(0),
                temporal_options
            )))
        );
    }

    #[test]
    fn validate_times_catch_too_old_token() {
        let temporal_options = TemporalOptions {
            now: Some(OffsetDateTime::from_unix_timestamp(40).unwrap()),
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            issued_at: Some(10.try_into().unwrap()),
            ..Default::default()
        };

        assert_eq!(
            Err(ValidationError::TooOld(Duration::seconds(5))),
            registered_claims.validate_iat(Validation::Validate((
                Duration::seconds(25),
                temporal_options
            )))
        );
    }

    #[test]
    fn validate_times_catch_expired_token() {
        let temporal_options = TemporalOptions {
            now: Some(OffsetDateTime::from_unix_timestamp(2).unwrap()),
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            expiry: Some(1.try_into().unwrap()),
            ..Default::default()
        };

        assert_eq!(
            Err(ValidationError::Expired(Duration::seconds(1))),
            registered_claims.validate_exp(Validation::Validate(temporal_options))
        );
    }

    #[test]
    fn validate_times_catch_early_token() {
        let temporal_options = TemporalOptions {
            now: Some(OffsetDateTime::from_unix_timestamp(0).unwrap()),
            ..Default::default()
        };

        let registered_claims = RegisteredClaims {
            not_before: Some(1.try_into().unwrap()),
            ..Default::default()
        };

        assert_eq!(
            Err(ValidationError::NotYetValid(Duration::seconds(1))),
            registered_claims.validate_nbf(Validation::Validate(temporal_options))
        );
    }

    #[test]
    fn validate_times_valid_token_with_default_options() {
        let registered_claims = RegisteredClaims {
            not_before: Some(Timestamp(OffsetDateTime::now_utc() - Duration::days(2))),
            issued_at: Some(Timestamp(OffsetDateTime::now_utc() - Duration::days(1))),
            expiry: Some(Timestamp(OffsetDateTime::now_utc() + Duration::days(1))),
            ..Default::default()
        };

        let validation_options = ValidationOptions {
            temporal_options: Default::default(),
            claim_presence_options: Default::default(),

            expiry: Validation::Validate(()),
            not_before: Validation::Validate(()),
            issued_at: Validation::Validate(Duration::MAX),

            ..Default::default()
        };

        registered_claims.validate(validation_options).unwrap();
    }

    #[test]
    fn validate_issuer_catch_mismatch() {
        let registered_claims = RegisteredClaims {
            issuer: Some("issuer".to_string()),
            ..Default::default()
        };

        assert_eq!(
            Err(ValidationError::InvalidIssuer("issuer".to_string())),
            registered_claims.validate_iss(Validation::Validate("http://issuer".to_string()))
        );
    }

    #[test]
    fn validate_audience_when_single() {
        let aud: SingleOrMultiple = "audience".into();

        let registered_claims = RegisteredClaims {
            audience: Some(aud.clone()),
            ..Default::default()
        };

        assert_eq!(
            Err(ValidationError::InvalidAudience(aud.clone())),
            registered_claims.validate_aud(Validation::Validate("http://audience".to_string()))
        );

        assert_eq!(
            Err(ValidationError::InvalidAudience(aud)),
            registered_claims.validate_aud(Validation::Validate("audience2".to_string()))
        );

        assert_eq!(
            Ok(()),
            registered_claims.validate_aud(Validation::Validate("audience".to_string()))
        );
    }

    #[test]
    fn validate_audience_when_multiple() {
        let aud =
            SingleOrMultiple::Multiple(vec!["audience".to_string(), "http://audience".to_string()]);

        let registered_claims = RegisteredClaims {
            audience: Some(aud.clone()),
            ..Default::default()
        };

        assert_eq!(
            Ok(()),
            registered_claims.validate_aud(Validation::Validate("http://audience".to_string()))
        );

        assert_eq!(
            Err(ValidationError::InvalidAudience(aud.clone())),
            registered_claims.validate_aud(Validation::Validate("audience2".to_string()))
        );

        assert_eq!(
            Err(ValidationError::InvalidAudience(aud)),
            registered_claims.validate_aud(Validation::Validate("https://audience".to_string()))
        );

        assert_eq!(
            Ok(()),
            registered_claims.validate_aud(Validation::Validate("audience".to_string()))
        );
    }

    #[test]
    fn validate_valid_token_with_all_required() {
        let registered_claims = RegisteredClaims {
            expiry: Some(999.try_into().unwrap()),
            not_before: Some(1.try_into().unwrap()),
            issued_at: Some(95.try_into().unwrap()),
            subject: Some("subject".to_string()),
            issuer: Some("issuer".to_string()),
            audience: Some(SingleOrMultiple::Multiple(vec![
                "http://audience".to_string(),
                "audience".to_string(),
            ])),
            id: Some("id".into()),
        };

        let temporal_options = TemporalOptions {
            now: Some(OffsetDateTime::from_unix_timestamp(100).unwrap()),
            ..Default::default()
        };

        let validation_options = ValidationOptions {
            temporal_options,
            claim_presence_options: ClaimPresenceOptions::strict(),

            expiry: Validation::Validate(()),
            not_before: Validation::Validate(()),
            issued_at: Validation::Validate(Duration::MAX),
            audience: Validation::Validate("audience".to_string()),
            issuer: Validation::Validate("issuer".to_string()),
        };

        registered_claims.validate(validation_options).unwrap();
    }

    #[test]
    fn validate_times_valid_token_with_epsilon() {
        let registered_claims = RegisteredClaims {
            expiry: Some(99.try_into().unwrap()),
            not_before: Some(96.try_into().unwrap()),
            issued_at: Some(96.try_into().unwrap()),
            ..Default::default()
        };

        let temporal_options = TemporalOptions {
            now: Some(OffsetDateTime::from_unix_timestamp(100).unwrap()),
            epsilon: Duration::seconds(10),
        };

        let validation_options = ValidationOptions {
            temporal_options,
            claim_presence_options: Default::default(),

            expiry: Validation::Validate(()),
            not_before: Validation::Validate(()),
            issued_at: Validation::Validate(Duration::MAX),

            ..Default::default()
        };

        registered_claims.validate(validation_options).unwrap();
    }
}
