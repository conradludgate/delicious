//! A library to work with Javascript Object Signing and Encryption(JOSE),
//! including JSON Web Tokens (JWT), JSON Web Signature (JWS) and JSON Web Encryption (JWE)
//!
//! ## Installation
//!
//! See [`JWT`] for common usage examples.
//!
//! ## Supported Features
//! The crate does not support all, and probably will never support all of
//! the features described in the various RFCs, including some algorithms and verification.
//!
//! ## References
//! - [JWT Handbook](https://auth0.com/e-books/jwt-handbook) — great introduction to JWT
//! - [IANA JOSE Registry](https://www.iana.org/assignments/jose/jose.xhtml)
//!
//! ### RFCs
//! - [JSON Web Tokens RFC](https://tools.ietf.org/html/rfc7519)
//! - [JSON Web Signature RFC](https://tools.ietf.org/html/rfc7515)
//! - [JSON Web Algorithms RFC](https://tools.ietf.org/html/rfc7518)
//! - [JSON Web Encryption RFC](https://tools.ietf.org/html/rfc7516)
//! - [JSON Web Signature (JWS) Unencoded Payload Option](https://tools.ietf.org/html/rfc7797)
//! - [CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE](https://tools.ietf.org/html/rfc8037)
//! - [JWS Unencoded Payload Option](https://tools.ietf.org/html/rfc7797)
//! - [JWK Thumbprint](https://tools.ietf.org/html/rfc7638)

#![allow(
    missing_copy_implementations,
    missing_debug_implementations,
    unknown_lints
)]
#![allow(
    clippy::try_err,
    clippy::needless_doctest_main,
    clippy::upper_case_acronyms
)]
#![deny(
    arithmetic_overflow,
    bad_style,
    const_err,
    dead_code,
    improper_ctypes,
    missing_docs,
    mutable_transmutes,
    no_mangle_const_items,
    non_camel_case_types,
    non_shorthand_field_patterns,
    non_upper_case_globals,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    stable_features,
    trivial_casts,
    trivial_numeric_casts,
    unconditional_recursion,
    unknown_crate_types,
    unreachable_code,
    unused_allocation,
    unused_assignments,
    unused_attributes,
    unused_comparisons,
    unused_extern_crates,
    unused_features,
    unused_import_braces,
    unused_imports,
    unused_must_use,
    unused_mut,
    unused_parens,
    unused_qualifications,
    unused_results,
    unused_unsafe,
    unused_variables,
    variant_size_differences,
    while_true
)]
#![doc(test(attr(allow(unused_variables), deny(warnings))))]

use std::borrow::Borrow;
use std::fmt::{self, Debug, Display};
use std::iter;
use std::ops::Deref;

use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use smallvec::SmallVec;
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

pub mod digest;

use crate::errors::{Error, ValidationError};

/// A convenience type alias of the common "JWT" which is a secured/unsecured compact JWS.
/// Type `T` is the type of the private claims, and type `H` is the type of private header fields
///
/// # Examples
/// ## Encoding and decoding with HS256
///
/// ```
/// use biscuit::*;
/// use biscuit::jws::*;
/// use biscuit::jwa::*;
/// use serde::{Serialize, Deserialize};
///
/// # fn main() {
///
/// // Define our own private claims
/// #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
/// struct PrivateClaims {
///     company: String,
///     department: String,
/// }
///
/// let signing_secret = Secret::Bytes("secret".to_string().into_bytes());
///
/// let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
///        eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1ZCI6Imh0dHBzOi8vYWNtZ\
///        S1jdXN0b21lci5jb20vIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2\
///        xlYW5pbmcifQ.VFCl2un1Kc17odzOe2Ehf4DVrWddu3U4Ux3GFpOZHtc";
///
/// let expected_claims = ClaimsSet::<PrivateClaims> {
///     registered: RegisteredClaims {
///         issuer: Some("https://www.acme.com/".to_string()),
///         subject: Some("John Doe".to_string()),
///         audience:
///             Some(SingleOrMultiple::Single("https://acme-customer.com/".to_string())),
///         not_before: Some(1234.into()),
///         ..Default::default()
///     },
///     private: PrivateClaims {
///         department: "Toilet Cleaning".to_string(),
///         company: "ACME".to_string(),
///     },
/// };
///
/// let expected_jwt = JWT::new_decoded(From::from(
///                                         RegisteredHeader {
///                                             algorithm: SignatureAlgorithm::HS256,
///                                             ..Default::default()
///                                         }),
///                                     expected_claims.clone());
///
/// let token = expected_jwt
///     .into_encoded(&signing_secret).unwrap();
/// let token = token.unwrap_encoded().to_string();
/// assert_eq!(expected_token, token);
/// // Now, send `token` to your clients
///
/// // ... some time later, we get token back!
///
/// let token = JWT::<_, biscuit::Empty>::new_encoded(&token);
/// let token = token.into_decoded(&signing_secret,
///     SignatureAlgorithm::HS256).unwrap();
/// assert_eq!(*token.payload().unwrap(), expected_claims);
/// # }
/// ```
pub type JWT<T, H> = jws::Decoded<ClaimsSet<T>, H>;

/// A convenience type alias of a "JWE" which is a compact JWE that contains a signed/unsigned compact JWS.
///
/// Type `T` is the type of private claims for the encapsulated JWT, and type `H` is the type of the private
/// header fields of the encapsulated JWT. Type `I` is the private header fields fo the encapsulating JWE.
///
/// Usually, you would set `H` and `I` to `biscuit::Empty` because you usually do not need any private header fields.
///
/// In general, you should [sign a JWT claims set, then encrypt it](http://crypto.stackexchange.com/a/5466),
/// although there is nothing stopping you from doing it the other way round.
///
/// # Examples
/// ## Sign with HS256, then encrypt with A256GCMKW and A256GCM
///
/// ```rust
/// use std::str::FromStr;
/// use biscuit::{ClaimsSet, RegisteredClaims, Empty, SingleOrMultiple, JWT, JWE};
/// use biscuit::jwk::JWK;
/// use biscuit::jws::{self, Secret};
/// use biscuit::jwe;
/// use biscuit::jwa::{EncryptionOptions, SignatureAlgorithm, KeyManagementAlgorithm,
///                    ContentEncryptionAlgorithm};
/// use serde::{Serialize, Deserialize};
///
/// // Define our own private claims
/// #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
/// struct PrivateClaims {
///     company: String,
///     department: String,
/// }
///
/// #[allow(unused_assignments)]
/// # fn main() {
/// // Craft our JWS
/// let expected_claims = ClaimsSet::<PrivateClaims> {
///     registered: RegisteredClaims {
///         issuer: Some(FromStr::from_str("https://www.acme.com").unwrap()),
///         subject: Some(FromStr::from_str("John Doe").unwrap()),
///         audience: Some(SingleOrMultiple::Single(
///             FromStr::from_str("htts://acme-customer.com").unwrap(),
///         )),
///         not_before: Some(1234.into()),
///         ..Default::default()
///     },
///     private: PrivateClaims {
///         department: "Toilet Cleaning".to_string(),
///         company: "ACME".to_string(),
///     },
/// };
///
/// let expected_jwt = JWT::new_decoded(
///     From::from(jws::RegisteredHeader {
///         algorithm: SignatureAlgorithm::HS256,
///         ..Default::default()
///     }),
///     expected_claims.clone(),
/// );
///
/// let jws = expected_jwt
///     .into_encoded(&Secret::Bytes("secret".to_string().into_bytes()))
///     .unwrap();
///
/// // Encrypt the token
///
/// // You would usually have your own AES key for this, but we will use a zeroed key as an example
/// let key: JWK<Empty> = JWK::new_octet_key(&vec![0; 256 / 8], Default::default());
///
/// // We need to create an `EncryptionOptions` with a nonce for AES GCM encryption.
/// // You must take care NOT to reuse the nonce. You can simply treat the nonce as a 96 bit
/// // counter that is incremented after every use
/// let mut nonce_counter = num_bigint::BigUint::from_bytes_le(&vec![0; 96 / 8]);
/// // Make sure it's no more than 96 bits!
/// assert!(nonce_counter.bits() <= 96);
/// let mut nonce_bytes = nonce_counter.to_bytes_le();
/// // We need to ensure it is exactly 96 bits
/// nonce_bytes.resize(96 / 8, 0);
/// let options = EncryptionOptions::AES_GCM { nonce: nonce_bytes };
///
/// // Construct the JWE
/// let jwe = JWE::new_decrypted(
///     From::from(jwe::RegisteredHeader {
///         cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
///         enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
///         media_type: Some("JOSE".to_string()),
///         content_type: Some("JOSE".to_string()),
///         ..Default::default()
///     }),
///     jws.clone(),
/// );
///
/// // Encrypt
/// let encrypted_jwe = jwe.encrypt(&key, &options).unwrap();
///
/// let token = encrypted_jwe.unwrap_encrypted().to_string();
///
/// // Now, send `token` to your clients
///
/// // ... some time later, we get token back!
/// let token: JWE<PrivateClaims, Empty, Empty> = JWE::new_encrypted(&token);
///
/// // Decrypt
/// let decrypted_jwe = token
///     .into_decrypted(
///         &key,
///         KeyManagementAlgorithm::A256GCMKW,
///         ContentEncryptionAlgorithm::A256GCM,
///     )
///     .unwrap();
///
/// let decrypted_jws = decrypted_jwe.payload().unwrap();
/// assert_eq!(jws, *decrypted_jws);
///
/// // Don't forget to increment the nonce!
/// nonce_counter = nonce_counter + 1u8;
/// # }
/// ```
pub type JWE<I> = jwe::Decrypted<Compact, I>;

/// An empty struct that derives Serialize and Deserialize. Can be used, for example, in places where a type
/// for custom values (such as private claims in a `ClaimsSet`) is required but you have nothing to implement.
///
/// # Examples
/// ```
/// use std::str::FromStr;
/// use biscuit::*;
/// use biscuit::jws::*;
/// use biscuit::jwa::*;
///
/// # fn main() {
///
/// let claims_set = ClaimsSet::<biscuit::Empty> {
///     registered: RegisteredClaims {
///         issuer: Some(FromStr::from_str("https://www.acme.com").unwrap()),
///         subject: Some(FromStr::from_str("John Doe").unwrap()),
///         audience:
///             Some(SingleOrMultiple::Single(FromStr::from_str("htts://acme-customer.com").unwrap())),
///         not_before: Some(1234.into()),
///         ..Default::default()
///     },
///     private: Default::default(),
/// };
///
/// let expected_jwt = JWT::new_decoded(From::from(
///                                         RegisteredHeader {
///                                             algorithm: SignatureAlgorithm::HS256,
///                                             ..Default::default()
///                                     }),
///                                     claims_set);
///
/// # }
/// ```
#[derive(Debug, Eq, PartialEq, Clone, Copy, Serialize, Deserialize, Default)]
pub struct Empty {}

/// A collection of `CompactPart`s that have been converted to `Base64Url`
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Compact {
    source: String,
    indices: SmallVec<[usize; 5]>,
}

impl Compact {
    /// Create an empty struct
    pub fn new() -> Self {
        Self {
            source: String::new(),
            indices: SmallVec::new(),
        }
    }

    /// Push a `CompactPart` to the end
    pub fn push(&mut self, part: &impl Serialize) -> Result<(), Error> {
        self.push_bytes(&serde_json::to_vec(part)?);
        Ok(())
    }

    /// Push a `CompactPart` to the end
    pub fn push_bytes(&mut self, input: &[u8]) {
        base64::encode_config_buf(input, base64::URL_SAFE_NO_PAD, &mut self.source);

        // push ending index
        self.indices.push(self.source.len());
        self.source.push('.');
    }

    /// Returns the number of parts
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// Returns whether there are no parts
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty() && self.source.is_empty()
    }

    /// Encodes the various parts into Base64 URL encoding and then concatenates them with period '.'
    /// This corresponds to the various `Compact` representation in JWE and JWS, for example
    pub fn into_inner(mut self) -> String {
        let _ = self.source.pop();
        self.source
    }

    /// Encodes the various parts into Base64 URL encoding and then concatenates them with period '.'
    /// This corresponds to the various `Compact` representation in JWE and JWS, for example
    pub fn as_str(&self) -> &str {
        let end = self.source.len().saturating_sub(1);
        &self.source[..end]
    }

    /// Convenience function to split an encoded compact representation into a list of `Base64Url`.
    pub fn decode(source: &str) -> Self {
        let mut indices = SmallVec::new();
        let mut source = source.to_owned();

        if !source.is_empty() {
            source.push('.');
            for (i, _) in source.match_indices('.') {
                indices.push(i);
            }
        }

        Self { source, indices }
    }

    /// Convenience function to retrieve a part at a certain index and decode into the type desired
    pub fn part(&self, index: usize) -> Result<&str, Error> {
        let end = *self
            .indices
            .get(index)
            .ok_or_else(|| "Out of bounds".to_string())?;
        let start = match index.checked_sub(1) {
            Some(i) => self.indices[i] + 1,
            None => 0,
        };
        Ok(&self.source[start..end])
    }

    /// Convenience function to retrieve a part at a certain index and decode into the type desired
    pub fn part_decoded(&self, index: usize) -> Result<Vec<u8>, Error> {
        Ok(base64::decode_config(
            self.part(index)?,
            base64::URL_SAFE_NO_PAD,
        )?)
    }

    /// Convenience function to retrieve a part at a certain index and decode into the type desired
    pub fn deser_part<T: DeserializeOwned>(&self, index: usize) -> Result<T, Error> {
        Ok(serde_json::from_slice(&self.part_decoded(index)?)?)
    }

    pub(crate) fn parse_triple(&self) -> Result<(&str, Vec<u8>), Error> {
        match self.indices.as_slice() {
            [_, x, y] => {
                let decode =
                    base64::decode_config(&self.source[x + 1..*y], base64::URL_SAFE_NO_PAD)?;
                Ok((&self.source[..*x], decode))
            }
            _ => Err(Error::DecodeError(
                crate::errors::DecodeError::PartsLengthError {
                    actual: self.len(),
                    expected: 3,
                },
            )),
        }
    }
}

impl Default for Compact {
    fn default() -> Self {
        Compact::new()
    }
}

impl Display for Compact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for Compact {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Compact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CompactVisitor;

        impl<'de> de::Visitor<'de> for CompactVisitor {
            type Value = Compact;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string containing a compact JOSE representation")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Compact::decode(value))
            }
        }

        deserializer.deserialize_str(CompactVisitor)
    }
}

/// Represents a choice between a single value or multiple values.
/// This value is serialized by serde [untagged](https://serde.rs/enum-representations.html).
///
/// # Examples
/// ```
/// use biscuit::SingleOrMultiple;
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
/// struct SingleOrMultipleStrings {
///     values: SingleOrMultiple<String>,
/// }
///
/// # fn main() {
/// let single = SingleOrMultipleStrings {
///     values: SingleOrMultiple::Single("foobar".to_string())
/// };
/// let expected_json = r#"{"values":"foobar"}"#;
///
/// let serialized = serde_json::to_string(&single).unwrap();
/// assert_eq!(expected_json, serialized);
///
/// let deserialized: SingleOrMultipleStrings = serde_json::from_str(&serialized).unwrap();
/// assert_eq!(deserialized, single);
///
/// let multiple = SingleOrMultipleStrings {
///     values: SingleOrMultiple::Multiple(vec!["foo".to_string(),
///                                             "bar".to_string(),
///                                             "baz".to_string()]),
/// };
///
/// let expected_json = r#"{"values":["foo","bar","baz"]}"#;
///
/// let serialized = serde_json::to_string(&multiple).unwrap();
/// assert_eq!(expected_json, serialized);
///
/// let deserialized: SingleOrMultipleStrings = serde_json::from_str(&serialized).unwrap();
/// assert_eq!(deserialized, multiple);
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SingleOrMultiple<T> {
    /// One single value
    Single(T),
    /// Multiple values
    Multiple(Vec<T>),
}

impl<T> SingleOrMultiple<T>
where
    T: Clone + Debug + Eq + PartialEq + Serialize + DeserializeOwned + Send + Sync,
{
    /// Checks whether this enum, regardless of single or multiple value contains `value`.
    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: ?Sized + PartialEq,
    {
        match *self {
            SingleOrMultiple::Single(ref single) => single.borrow() == value,
            SingleOrMultiple::Multiple(ref vector) => {
                vector.iter().map(Borrow::borrow).any(|v| v == value)
            }
        }
    }

    /// Yields an iterator for the single value or the list
    pub fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a T> + 'a> {
        match *self {
            SingleOrMultiple::Single(ref single) => Box::new(iter::once(single)),
            SingleOrMultiple::Multiple(ref vector) => Box::new(vector.iter()),
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
    pub audience: Option<SingleOrMultiple<String>>,

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
        use crate::Presence::Required;
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
            Validation::Validate(expected_aud) => match self.audience {
                Some(SingleOrMultiple::Single(ref audience)) if audience != &expected_aud => Err(
                    ValidationError::InvalidAudience(SingleOrMultiple::Single(audience.clone())),
                ),
                Some(SingleOrMultiple::Multiple(ref audiences))
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

// impl<T> CompactJson for ClaimsSet<T> where T: Serialize + DeserializeOwned {}

#[cfg(test)]
mod tests {
    use std::str::{self, FromStr};

    use time::Duration;

    use super::*;

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
        values: SingleOrMultiple<String>,
    }

    #[test]
    fn single_string_serialization_round_trip() {
        let test = SingleOrMultipleStrings {
            values: SingleOrMultiple::Single("foobar".to_string()),
        };
        let expected_json = r#"{"values":"foobar"}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStrings = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);
        assert!(deserialized.values.contains("foobar"));
        assert!(!deserialized.values.contains("does not exist"));
    }

    #[test]
    fn multiple_strings_serialization_round_trip() {
        let test = SingleOrMultipleStrings {
            values: SingleOrMultiple::Multiple(vec![
                "foo".to_string(),
                "bar".to_string(),
                "baz".to_string(),
            ]),
        };
        let expected_json = r#"{"values":["foo","bar","baz"]}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStrings = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);
        assert!(deserialized.values.contains("foo"));
        assert!(deserialized.values.contains("bar"));
        assert!(deserialized.values.contains("baz"));
        assert!(!deserialized.values.contains("does not exist"));
    }

    #[test]
    fn single_string_or_uri_string_serialization_round_trip() {
        let test = SingleOrMultipleStrings {
            values: SingleOrMultiple::Single(not_err!(FromStr::from_str("foobar"))),
        };
        let expected_json = r#"{"values":"foobar"}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStrings = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);
        assert!(deserialized.values.contains("foobar"));
        assert!(!deserialized.values.contains("does not exist"));
    }

    #[test]
    fn single_string_or_uri_uri_serialization_round_trip() {
        let test = SingleOrMultipleStrings {
            values: SingleOrMultiple::Single(not_err!(FromStr::from_str(
                "https://www.examples.com/"
            ))),
        };
        let expected_json = r#"{"values":"https://www.examples.com/"}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStrings = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, test);
        assert!(deserialized.values.contains("https://www.examples.com/"));
        assert!(!deserialized.values.contains("https://ecorp.com"));
    }

    #[test]
    fn multiple_string_or_uri_serialization_round_trip() {
        let test = SingleOrMultipleStrings {
            values: SingleOrMultiple::Multiple(vec![
                not_err!(FromStr::from_str("foo")),
                not_err!(FromStr::from_str("https://www.example.com/")),
                not_err!(FromStr::from_str("data:text/plain,Hello?World#")),
                not_err!(FromStr::from_str("http://[::1]/")),
                not_err!(FromStr::from_str("baz")),
            ]),
        };
        let expected_json = r#"{"values":["foo","https://www.example.com/","data:text/plain,Hello?World#","http://[::1]/","baz"]}"#;

        let serialized = not_err!(serde_json::to_string(&test));
        assert_eq!(expected_json, serialized);

        let deserialized: SingleOrMultipleStrings = not_err!(serde_json::from_str(&serialized));
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
        let serialized = not_err!(serde_json::to_string(&now));
        let deserialized = not_err!(serde_json::from_str(&serialized));
        assert_eq!(now, deserialized);

        let fixed_time: Timestamp = 1000.try_into().unwrap();
        let serialized = not_err!(serde_json::to_string(&fixed_time));
        assert_eq!(serialized, "1000");
        let deserialized = not_err!(serde_json::from_str(&serialized));
        assert_eq!(fixed_time, deserialized);
    }

    #[test]
    fn empty_registered_claims_serialization_round_trip() {
        let claim = RegisteredClaims::default();
        let expected_json = "{}";

        let serialized = not_err!(serde_json::to_string(&claim));
        assert_eq!(expected_json, serialized);

        let deserialized: RegisteredClaims = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, claim);
    }

    #[test]
    fn registered_claims_serialization_round_trip() {
        let claim = RegisteredClaims {
            issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
            audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                "htts://acme-customer.com/"
            )))),
            not_before: Some(1234.try_into().unwrap()),
            ..Default::default()
        };
        let expected_json =
            r#"{"iss":"https://www.acme.com/","aud":"htts://acme-customer.com/","nbf":1234}"#;

        let serialized = not_err!(serde_json::to_string(&claim));
        assert_eq!(expected_json, serialized);

        let deserialized: RegisteredClaims = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, claim);
    }

    #[test]
    fn claims_set_serialization_round_trip() {
        let claim = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "htts://acme-customer.com/"
                )))),
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

        let serialized = not_err!(serde_json::to_string(&claim));
        assert_eq!(expected_json, serialized);

        let deserialized: ClaimsSet<PrivateClaims> = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, claim);
    }

    #[test]
    // serde's flatten will serialize them twice
    fn duplicate_claims_round_trip() {
        let claim = ClaimsSet::<InvalidPrivateClaim> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "htts://acme-customer.com"
                )))),
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
        let registered_claims: RegisteredClaims = Default::default();
        let options = ClaimPresenceOptions {
            issued_at: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"exp\"])")]
    fn validate_times_missing_exp() {
        let registered_claims: RegisteredClaims = Default::default();
        let options = ClaimPresenceOptions {
            expiry: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"nbf\"])")]
    fn validate_times_missing_nbf() {
        let registered_claims: RegisteredClaims = Default::default();
        let options = ClaimPresenceOptions {
            not_before: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"aud\"])")]
    fn validate_times_missing_aud() {
        let registered_claims: RegisteredClaims = Default::default();
        let options = ClaimPresenceOptions {
            audience: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"iss\"])")]
    fn validate_times_missing_iss() {
        let registered_claims: RegisteredClaims = Default::default();
        let options = ClaimPresenceOptions {
            issuer: Presence::Required,
            ..Default::default()
        };
        registered_claims.validate_claim_presence(options).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingRequiredClaims([\"sub\"])")]
    fn validate_times_missing_sub() {
        let registered_claims: RegisteredClaims = Default::default();
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
        let registered_claims: RegisteredClaims = Default::default();
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

        not_err!(registered_claims.validate(validation_options));
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
        let aud = SingleOrMultiple::Single("audience".to_string());

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

        not_err!(registered_claims.validate(validation_options));
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

        not_err!(registered_claims.validate(validation_options));
    }
}
