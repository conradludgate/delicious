//! [JSON Web Encryption](https://tools.ietf.org/html/rfc7516)
//!
//! This module contains code to implement JWE, the JOSE standard to encrypt arbitrary payloads.
//! Most commonly, JWE is used to encrypt a JWS payload, which is a signed JWT. For most common use,
//! you will want to look at the  [`Compact`](enum.Compact.html) enum.
use std::fmt;

use serde::de::{self, DeserializeOwned};
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

use crate::errors::{DecodeError, Error, ValidationError};
use crate::jwa::{
    self, ContentEncryptionAlgorithm, EncryptionOptions, EncryptionResult, KeyManagementAlgorithm,
};
use crate::jwk;
use crate::Empty;

#[derive(Debug, Eq, PartialEq, Clone)]
/// Compression algorithm applied to plaintext before encryption.
pub enum CompressionAlgorithm {
    /// DEFLATE algorithm defined in [RFC 1951](https://tools.ietf.org/html/rfc1951)
    Deflate,
    /// Other user-defined algorithm
    Other(String),
}

impl Serialize for CompressionAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string = match *self {
            CompressionAlgorithm::Deflate => "DEF",
            CompressionAlgorithm::Other(ref other) => other,
        };

        serializer.serialize_str(string)
    }
}

impl<'de> Deserialize<'de> for CompressionAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CompressionAlgorithmVisitor;
        impl<'de> de::Visitor<'de> for CompressionAlgorithmVisitor {
            type Value = CompressionAlgorithm;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(match v {
                    "DEF" => CompressionAlgorithm::Deflate,
                    other => CompressionAlgorithm::Other(other.to_string()),
                })
            }
        }

        deserializer.deserialize_string(CompressionAlgorithmVisitor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
/// Registered JWE header fields.
/// The fields are defined by [RFC 7516#4.1](https://tools.ietf.org/html/rfc7516#section-4.1)
pub struct RegisteredHeader {
    /// Algorithm used to encrypt or determine the value of the Content Encryption Key
    #[serde(rename = "alg")]
    pub cek_algorithm: KeyManagementAlgorithm,

    /// Content encryption algorithm used to perform authenticated encryption
    /// on the plaintext to produce the ciphertext and the Authentication Tag
    #[serde(rename = "enc")]
    pub enc_algorithm: ContentEncryptionAlgorithm,

    /// Compression algorithm applied to plaintext before encryption, if any.
    /// Compression is not supported at the moment.
    /// _Must only appear in integrity protected header._
    #[serde(rename = "zip", skip_serializing_if = "Option::is_none")]
    pub compression_algorithm: Option<CompressionAlgorithm>,

    /// Media type of the complete JWE. Serialized to `typ`.
    /// Defined in [RFC7519#5.1](https://tools.ietf.org/html/rfc7519#section-5.1) and additionally
    /// [RFC7515#4.1.9](https://tools.ietf.org/html/rfc7515#section-4.1.9).
    /// The "typ" value "JOSE" can be used by applications to indicate that
    /// this object is a JWS or JWE using the JWS Compact Serialization or
    /// the JWE Compact Serialization.  The "typ" value "JOSE+JSON" can be
    /// used by applications to indicate that this object is a JWS or JWE
    /// using the JWS JSON Serialization or the JWE JSON Serialization.
    /// Other type values can also be used by applications.
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// Content Type of the secured payload.
    /// Typically used to indicate the presence of a nested JOSE object which is signed or encrypted.
    /// Serialized to `cty`.
    /// Defined in [RFC7519#5.2](https://tools.ietf.org/html/rfc7519#section-5.2) and additionally
    /// [RFC7515#4.1.10](https://tools.ietf.org/html/rfc7515#section-4.1.10).
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// The JSON Web Key Set URL. This is currently not implemented (correctly).
    /// Serialized to `jku`.
    /// Defined in [RFC7515#4.1.2](https://tools.ietf.org/html/rfc7515#section-4.1.2).
    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    pub web_key_url: Option<String>,

    /// The JSON Web Key. This is currently not implemented (correctly).
    /// Serialized to `jwk`.
    /// Defined in [RFC7515#4.1.3](https://tools.ietf.org/html/rfc7515#section-4.1.3).
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub web_key: Option<String>,

    /// The Key ID. This is currently not implemented (correctly).
    /// Serialized to `kid`.
    /// Defined in [RFC7515#4.1.3](https://tools.ietf.org/html/rfc7515#section-4.1.3).
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// X.509 Public key cerfificate URL. This is currently not implemented (correctly).
    /// Serialized to `x5u`.
    /// Defined in [RFC7515#4.1.5](https://tools.ietf.org/html/rfc7515#section-4.1.5).
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<String>,

    /// X.509 public key certificate chain. This is currently not implemented (correctly).
    /// Serialized to `x5c`.
    /// Defined in [RFC7515#4.1.6](https://tools.ietf.org/html/rfc7515#section-4.1.6).
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub x509_chain: Option<Vec<String>>,

    /// X.509 Certificate thumbprint. This is currently not implemented (correctly).
    /// Also not implemented, is the SHA-256 thumbprint variant of this header.
    /// Serialized to `x5t`.
    /// Defined in [RFC7515#4.1.7](https://tools.ietf.org/html/rfc7515#section-4.1.7).
    // TODO: How to make sure the headers are mutually exclusive?
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub x509_fingerprint: Option<String>,

    /// List of critical extended headers.
    /// This is currently not implemented (correctly).
    /// Serialized to `crit`.
    /// Defined in [RFC7515#4.1.11](https://tools.ietf.org/html/rfc7515#section-4.1.11).
    #[serde(rename = "crit", skip_serializing_if = "Option::is_none")]
    pub critical: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
/// Headers specific to the Key management algorithm used. Users should typically not construct these fields as they
/// will be filled in automatically when encrypting and stripped when decrypting
pub struct CekAlgorithmHeader {
    /// Header for AES GCM Keywrap algorithm.
    /// The initialization vector, or nonce used in the encryption
    #[serde(rename = "iv", skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Vec<u8>>,

    /// Header for AES GCM Keywrap algorithm.
    /// The authentication tag resulting from the encryption
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<Vec<u8>>,
}

/// JWE Header, consisting of the registered fields and other custom fields
#[derive(Debug, Eq, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct Header<T> {
    /// Registered header fields
    #[serde(flatten)]
    pub registered: RegisteredHeader,
    /// Key management algorithm specific headers
    #[serde(flatten)]
    pub cek_algorithm: CekAlgorithmHeader,
    /// Private header fields
    #[serde(flatten)]
    pub private: T,
}

// impl<T: Serialize + DeserializeOwned> CompactJson for Header<T> {}

impl<T: Serialize + DeserializeOwned> Header<T> {
    /// Update CEK algorithm specific header fields based on a CEK encryption result
    fn update_cek_algorithm(&mut self, encrypted: &EncryptionResult) {
        if !encrypted.nonce.is_empty() {
            self.cek_algorithm.nonce = Some(encrypted.nonce.clone());
        }

        if !encrypted.tag.is_empty() {
            self.cek_algorithm.tag = Some(encrypted.tag.clone());
        }
    }

    /// Extract the relevant fields from the header to build an `EncryptionResult` and strip them from the header
    fn extract_cek_encryption_result(&mut self, encrypted_payload: &[u8]) -> EncryptionResult {
        let result = EncryptionResult {
            encrypted: encrypted_payload.to_vec(),
            nonce: self.cek_algorithm.nonce.clone().unwrap_or_default(),
            tag: self.cek_algorithm.tag.clone().unwrap_or_default(),
            ..Default::default()
        };

        self.cek_algorithm = Default::default();
        result
    }
}

impl Header<Empty> {
    /// Convenience function to create a header with only registered headers
    pub fn from_registered_header(registered: RegisteredHeader) -> Self {
        Self {
            registered,
            ..Default::default()
        }
    }
}

impl From<RegisteredHeader> for Header<Empty> {
    fn from(registered: RegisteredHeader) -> Self {
        Self::from_registered_header(registered)
    }
}

// /// Compact representation of a JWE, or an encrypted JWT
// ///
// /// This representation contains a payload of type `T` with custom headers provided by type `H`.
// /// In general you should use a JWE with a JWS. That is, you should sign your JSON Web Token to
// /// create a JWS, and then encrypt the signed JWS.
// ///
// /// # Nonce/Initialization Vectors for AES GCM encryption
// ///
// /// When encrypting tokens with AES GCM, you must take care _not to reuse_ the nonce for the same
// /// key. You can keep track of this by simply treating the nonce as a 96 bit counter and
// /// incrementing it every time you encrypt something new.
// ///
// /// # Examples
// /// ## Encrypting a JWS/JWT
// /// See the example code in the [`biscuit::JWE`](../type.JWE.html) type alias.
// ///
// /// ## Encrypting a string payload with A256GCMKW and A256GCM
// /// ```
// /// use std::str;
// /// use biscuit::Empty;
// /// use biscuit::jwk::JWK;
// /// use biscuit::jwe;
// /// use biscuit::jwa::{EncryptionOptions, KeyManagementAlgorithm, ContentEncryptionAlgorithm};
// ///
// /// # #[allow(unused_assignments)]
// /// # fn main() {
// /// let payload = "The true sign of intelligence is not knowledge but imagination.";
// /// // You would usually have your own AES key for this, but we will use a zeroed key as an example
// /// let key: JWK<Empty> = JWK::new_octet_key(&vec![0; 256 / 8], Default::default());
// ///
// /// // Construct the JWE
// /// let jwe = jwe::Decrypted::new(
// ///     From::from(jwe::RegisteredHeader {
// ///         cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
// ///         enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
// ///         ..Default::default()
// ///     }),
// ///     payload.as_bytes().to_vec(),
// /// );
// ///
// /// // We need to create an `EncryptionOptions` with a nonce for AES GCM encryption.
// /// // You must take care NOT to reuse the nonce. You can simply treat the nonce as a 96 bit
// /// // counter that is incremented after every use
// /// let mut nonce_counter = num_bigint::BigUint::from_bytes_le(&vec![0; 96 / 8]);
// /// // Make sure it's no more than 96 bits!
// /// assert!(nonce_counter.bits() <= 96);
// /// let mut nonce_bytes = nonce_counter.to_bytes_le();
// /// // We need to ensure it is exactly 96 bits
// /// nonce_bytes.resize(96/8, 0);
// /// let options = EncryptionOptions::AES_GCM { nonce: nonce_bytes };
// ///
// /// // Encrypt
// /// let encrypted_jwe = jwe.encrypt(&key, &options).unwrap();
// ///
// /// // Decrypt
// /// let decrypted_jwe = encrypted_jwe
// ///     .decrypt(
// ///         &key,
// ///         KeyManagementAlgorithm::A256GCMKW,
// ///         ContentEncryptionAlgorithm::A256GCM,
// ///     )
// ///     .unwrap();
// ///
// /// let decrypted_payload: &Vec<u8> = decrypted_jwe.payload().unwrap();
// /// let decrypted_str = str::from_utf8(&*decrypted_payload).unwrap();
// /// assert_eq!(decrypted_str, payload);
// ///
// /// // Don't forget to increment the nonce!
// /// nonce_counter = nonce_counter + 1u8;
// /// # }
// /// ```
// #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
// #[serde(untagged)]
// pub enum Compact<T, H> {
//     /// Decrypted form of the JWE.
//     /// This variant cannot be serialized or deserialized and will return an error.
//     #[serde(skip_serializing)]
//     #[serde(skip_deserializing)]
//     Decrypted {
//         /// Embedded header
//         header: Header<H>,
//         /// Payload, usually a signed/unsigned JWT
//         payload: T,
//     },
//     /// Encrypted JWT. Use this form to send to your clients
//     Encrypted(crate::Compact),
// }

/// Rust representation of a JWE
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decrypted<T, H> {
    /// Embedded header
    header: Header<H>,
    /// Payload, usually a signed/unsigned JWT
    payload: T,
}

impl<T, H> Decrypted<T, H>
where
    T: Serialize + DeserializeOwned,
    H: Serialize + DeserializeOwned + Clone,
{
    /// Create a new encrypted JWE
    pub fn new(header: Header<H>, payload: T) -> Self {
        Self { header, payload }
    }

    // /// Create a new encrypted JWE
    // pub fn new_encrypted(token: &str) -> Self {
    //     Compact::Encrypted(crate::Compact::decode(&token.to_owned()))
    // }

    // /// Consumes self and encrypt it. If the token is already encrypted, this is a no-op.
    // ///
    // /// You will need to provide a `jwa::EncryptionOptions` that will differ based on your chosen
    // /// algorithms.
    // ///
    // /// If your `cek_algorithm` is not `dir` or direct, the options provided will be used to
    // /// encrypt your content encryption key.
    // ///
    // /// If your `cek_algorithm` is `dir` or Direct, then the options will be used to encrypt
    // /// your content directly.
    // pub fn into_encrypted<K: Serialize + DeserializeOwned>(
    //     self,
    //     key: &jwk::JWK<K>,
    //     options: &EncryptionOptions,
    // ) -> Result<Self, Error> {
    //     match self {
    //         Compact::Encrypted(_) => Ok(self),
    //         Compact::Decrypted { .. } => self.encrypt(key, options),
    //     }
    // }

    /// Encrypt an Decrypted JWE.
    ///
    /// You will need to provide a `jwa::EncryptionOptions` that will differ based on your chosen
    /// algorithms.
    ///
    /// If your `cek_algorithm` is not `dir` or direct, the options provided will be used to
    /// encrypt your content encryption key.
    ///
    /// If your `cek_algorithm` is `dir` or Direct, then the options will be used to encrypt
    /// your content directly.
    pub fn encrypt<K: Serialize + DeserializeOwned>(
        &self,
        key: &jwk::JWK<K>,
        options: &EncryptionOptions,
    ) -> Result<crate::Compact, Error> {
        use std::borrow::Cow;

        // Resolve encryption option
        let (key_option, content_option): (_, Cow<'_, _>) =
            match self.header.registered.cek_algorithm {
                KeyManagementAlgorithm::DirectSymmetricKey => {
                    (jwa::NONE_ENCRYPTION_OPTIONS, Cow::Borrowed(options))
                }
                _ => (
                    options,
                    Cow::Owned(
                        self.header
                            .registered
                            .enc_algorithm
                            .random_encryption_options()?,
                    ),
                ),
            };

        // RFC 7516 Section 5.1 describes the steps involved in encryption.
        // From steps 1 to 8, we will first determine the CEK, and then encrypt the CEK.
        let cek = self
            .header
            .registered
            .cek_algorithm
            .cek(self.header.registered.enc_algorithm, key)?;
        let encrypted_cek = self.header.registered.cek_algorithm.wrap_key(
            cek.algorithm.octet_key()?,
            key,
            key_option,
        )?;
        // Update header
        let mut header = self.header.clone();
        header.update_cek_algorithm(&encrypted_cek);

        // Steps 9 and 10 involves calculating an initialization vector (nonce) for content encryption. We do
        // this as part of the encryption process later

        // Step 11 involves compressing the payload, which we do not support at the moment
        let payload = serde_json::to_vec(&self.payload)?;
        if header.registered.compression_algorithm.is_some() {
            Err(Error::UnsupportedOperation)?
        }

        // Steps 12 to 14 involves the calculation of `Additional Authenticated Data` for encryption. In
        // our compact example, our header is the AAD.
        let encoded_protected_header =
            base64::encode_config(&serde_json::to_vec(&header)?, base64::URL_SAFE_NO_PAD);
        // Step 15 involves the actual encryption.
        let encrypted_payload = header.registered.enc_algorithm.encrypt(
            &payload,
            encoded_protected_header.as_bytes(),
            &cek,
            &content_option,
        )?;

        // Finally create the JWE
        let mut compact = crate::Compact::new();
        compact.push(&header)?;
        compact.push_bytes(&encrypted_cek.encrypted);
        compact.push_bytes(&encrypted_payload.nonce);
        compact.push_bytes(&encrypted_payload.encrypted);
        compact.push_bytes(&encrypted_payload.tag);

        Ok(compact)
    }

    // /// Consumes self and decrypt it. If the token is already decrypted,
    // /// this is a no-op.
    // pub fn into_decrypted<K: Serialize + DeserializeOwned>(
    //     self,
    //     key: &jwk::JWK<K>,
    //     cek_alg: KeyManagementAlgorithm,
    //     enc_alg: ContentEncryptionAlgorithm,
    // ) -> Result<Self, Error> {
    //     match self {
    //         Compact::Encrypted(_) => self.decrypt(key, cek_alg, enc_alg),
    //         Compact::Decrypted { .. } => Ok(self),
    //     }
    // }

    /// Decrypt an encrypted JWE. Provide the expected algorithms to mitigate an attacker modifying the
    /// fields
    pub fn decrypt<K: Serialize + DeserializeOwned>(
        encrypted: &crate::Compact,
        key: &jwk::JWK<K>,
        cek_alg: KeyManagementAlgorithm,
        enc_alg: ContentEncryptionAlgorithm,
    ) -> Result<Self, Error> {
        if encrypted.len() != 5 {
            Err(DecodeError::PartsLengthError {
                actual: encrypted.len(),
                expected: 5,
            })?
        }
        // RFC 7516 Section 5.2 describes the steps involved in decryption.
        // Steps 1-3
        let mut header: Header<H> = encrypted.deser_part(0)?;
        let encrypted_cek = encrypted.part_decoded(1)?;
        let nonce = encrypted.part_decoded(2)?;
        let encrypted_payload = encrypted.part_decoded(3)?;
        let tag = encrypted.part_decoded(4)?;

        // Verify that the algorithms are expected
        if header.registered.cek_algorithm != cek_alg || header.registered.enc_algorithm != enc_alg
        {
            Err(Error::ValidationError(
                ValidationError::WrongAlgorithmHeader,
            ))?;
        }

        // TODO: Steps 4-5 not implemented at the moment.

        // Steps 6-13 involve the computation of the cek
        let cek_encryption_result = header.extract_cek_encryption_result(&encrypted_cek);
        let cek = header.registered.cek_algorithm.unwrap_key(
            &cek_encryption_result,
            header.registered.enc_algorithm,
            key,
        )?;

        // Build encryption result as per steps 14-15
        let encoded_protected_header = encrypted.part(0)?;
        let encrypted_payload_result = EncryptionResult {
            nonce,
            tag,
            encrypted: encrypted_payload,
            additional_data: encoded_protected_header.as_bytes().to_vec(),
        };

        let payload = header
            .registered
            .enc_algorithm
            .decrypt(&encrypted_payload_result, &cek)?;

        // Decompression is not supported at the moment
        if header.registered.compression_algorithm.is_some() {
            Err(Error::UnsupportedOperation)?
        }

        let payload = serde_json::from_slice::<T>(&payload)?;

        Ok(Self::new(header, payload))
    }

    // /// Convenience method to get a reference to the encrypted payload
    // pub fn encrypted(&self) -> Result<&crate::Compact, Error> {
    //     match *self {
    //         Compact::Decrypted { .. } => Err(Error::UnsupportedOperation),
    //         Compact::Encrypted(ref encoded) => Ok(encoded),
    //     }
    // }

    // /// Convenience method to get a mutable reference to the encrypted payload
    // pub fn encrypted_mut(&mut self) -> Result<&mut crate::Compact, Error> {
    //     match *self {
    //         Compact::Decrypted { .. } => Err(Error::UnsupportedOperation),
    //         Compact::Encrypted(ref mut encoded) => Ok(encoded),
    //     }
    // }

    // /// Convenience method to get a reference to the payload from an Decrypted JWE
    // pub fn payload(&self) -> Result<&T, Error> {
    //     match *self {
    //         Compact::Decrypted { ref payload, .. } => Ok(payload),
    //         Compact::Encrypted(_) => Err(Error::UnsupportedOperation),
    //     }
    // }

    // /// Convenience method to get a mutable reference to the payload from an Decrypted JWE
    // pub fn payload_mut(&mut self) -> Result<&mut T, Error> {
    //     match *self {
    //         Compact::Decrypted {
    //             ref mut payload, ..
    //         } => Ok(payload),
    //         Compact::Encrypted(_) => Err(Error::UnsupportedOperation),
    //     }
    // }

    // /// Convenience method to get a reference to the header from an Decrypted JWE
    // pub fn header(&self) -> Result<&Header<H>, Error> {
    //     match *self {
    //         Compact::Decrypted { ref header, .. } => Ok(header),
    //         Compact::Encrypted(_) => Err(Error::UnsupportedOperation),
    //     }
    // }

    // /// Convenience method to get a reference to the header from an Decrypted JWE
    // pub fn header_mut(&mut self) -> Result<&mut Header<H>, Error> {
    //     match *self {
    //         Compact::Decrypted { ref mut header, .. } => Ok(header),
    //         Compact::Encrypted(_) => Err(Error::UnsupportedOperation),
    //     }
    // }

    // /// Consumes self, and move the payload and header out and return them as a tuple
    // ///
    // /// # Panics
    // /// Panics if the JWE is not decrypted
    // pub fn unwrap_decrypted(self) -> (Header<H>, T) {
    //     match self {
    //         Compact::Decrypted { header, payload } => (header, payload),
    //         Compact::Encrypted(_) => panic!("JWE is encrypted"),
    //     }
    // }

    // /// Consumes self, and move the encrypted Compact serialization out and return it
    // ///
    // /// # Panics
    // /// Panics if the JWE is not encrypted
    // pub fn unwrap_encrypted(self) -> crate::Compact {
    //     match self {
    //         Compact::Decrypted { .. } => panic!("JWE is decrypted"),
    //         Compact::Encrypted(compact) => compact,
    //     }
    // }
}

/// Convenience implementation for a Compact that contains a `ClaimsSet`
impl<P, H> Decrypted<crate::ClaimsSet<P>, H>
where
    crate::ClaimsSet<P>: Serialize + DeserializeOwned,
    H: Serialize + DeserializeOwned + Clone,
{
    /// Validate the temporal claims in the decoded token
    ///
    /// If `None` is provided for options, the defaults will apply.
    ///
    /// By default, no temporal claims (namely `iat`, `exp`, `nbf`)
    /// are required, and they will pass validation if they are missing.
    pub fn validate(&self, options: crate::ValidationOptions) -> Result<(), Error> {
        self.payload.registered.validate(options)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ring::rand::SecureRandom;
    use serde_test::{assert_tokens, Token};

    use super::*;
    use crate::jwa::{self, random_aes_gcm_nonce, rng};
    use crate::test::assert_serde_json;
    use crate::{jws, Compact};

    fn cek_oct_key(len: usize) -> jwk::JWK<Empty> {
        // Construct the encryption key
        let mut key: Vec<u8> = vec![0; len];
        not_err!(rng().fill(&mut key));
        jwk::JWK {
            common: Default::default(),
            additional: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                key_type: Default::default(),
                value: key,
            }),
        }
    }

    #[test]
    fn compression_algorithm_serde_token() {
        #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
        struct Test {
            test: CompressionAlgorithm,
        }

        let test_value = Test {
            test: CompressionAlgorithm::Deflate,
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("DEF"),
                Token::StructEnd,
            ],
        );

        let test_value = Test {
            test: CompressionAlgorithm::Other("xxx".to_string()),
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("xxx"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn compression_algorithm_json_serde() {
        #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
        struct Test {
            test: CompressionAlgorithm,
        }

        let test_json = r#"{"test": "DEF"}"#;
        assert_serde_json(
            &Test {
                test: CompressionAlgorithm::Deflate,
            },
            Some(test_json),
        );

        let test_json = r#"{"test": "xxx"}"#;
        assert_serde_json(
            &Test {
                test: CompressionAlgorithm::Other("xxx".to_string()),
            },
            Some(test_json),
        );
    }

    #[test]
    fn jwe_interoperability_check() {
        // This test vector is created by using python-jwcrypto (https://jwcrypto.readthedocs.io/en/latest/)
        /*
          from jwcrypto import jwk, jwe
          from jwcrypto.common import json_encode
          key = jwk.JWK.generate(kty='oct', size=256)
          payload = '"Encrypted"'
          jwetoken = jwe.JWE(payload.encode('utf-8'),
                             json_encode({"alg": "dir",
                                          "enc": "A256GCM"}))
          jwetoken.add_recipient(key)
          jwetoken.serialize()
          key.export()
        */
        let external_token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..fHhEyBZ9S4CsGi1Y.gnTZjScRZu22rvk.F8SJn0TUAus8w_TaItsOJw";
        let key_json = r#"{"k":"-wcjSeVOJ0V43ij5uDBeFlOR1w2T40jqIfICQb8-sUw","kty":"oct"}"#;

        let key: jwk::JWK<Empty> = not_err!(serde_json::from_str(key_json));
        let token: Compact = Compact::decode(external_token);

        let decrypted_jwe = not_err!(Decrypted::<String, Empty>::decrypt(
            &token,
            &key,
            jwa::KeyManagementAlgorithm::DirectSymmetricKey,
            jwa::ContentEncryptionAlgorithm::A256GCM,
        ));

        let decrypted_payload = decrypted_jwe.payload;
        assert_eq!(decrypted_payload, "Encrypted");
    }

    #[test]
    fn jwe_header_round_trips() {
        let test_value: Header<Empty> = From::from(RegisteredHeader {
            cek_algorithm: KeyManagementAlgorithm::RSA_OAEP,
            enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
            ..Default::default()
        });
        let test_json = r#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#;
        assert_serde_json(&test_value, Some(test_json));

        let test_value: Header<Empty> = From::from(RegisteredHeader {
            cek_algorithm: KeyManagementAlgorithm::RSA1_5,
            enc_algorithm: ContentEncryptionAlgorithm::A128CBC_HS256,
            ..Default::default()
        });
        let test_json = r#"{"alg":"RSA1_5","enc":"A128CBC-HS256"}"#;
        assert_serde_json(&test_value, Some(test_json));

        let test_value: Header<Empty> = From::from(RegisteredHeader {
            cek_algorithm: KeyManagementAlgorithm::A128KW,
            enc_algorithm: ContentEncryptionAlgorithm::A128CBC_HS256,
            ..Default::default()
        });
        let test_json = r#"{"alg":"A128KW","enc":"A128CBC-HS256"}"#;
        assert_serde_json(&test_value, Some(test_json));
    }

    #[test]
    fn custom_jwe_header_round_trip() {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct CustomHeader {
            something: String,
        }

        let test_value = Header {
            registered: RegisteredHeader {
                cek_algorithm: KeyManagementAlgorithm::RSA_OAEP,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            },
            cek_algorithm: Default::default(),
            private: CustomHeader {
                something: "foobar".to_string(),
            },
        };
        let test_json = r#"{"alg":"RSA-OAEP","enc":"A256GCM","something":"foobar"}"#;
        assert_serde_json(&test_value, Some(test_json));
    }

    #[test]
    fn jwe_a256gcmkw_a256gcm_string_round_trip() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload =
            String::from("The true sign of intelligence is not knowledge but imagination.");
        let jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.clone(),
        );
        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };

        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &options));

        {
            // Check that new header values are added
            let compact = encrypted_jwe.clone();
            let header: Header<Empty> = compact.deser_part(0).unwrap();
            assert!(header.cek_algorithm.nonce.is_some());
            assert!(header.cek_algorithm.tag.is_some());

            // Check that the encrypted key part is not empty
            let cek: Vec<u8> = compact.part_decoded(1).unwrap();
            assert_eq!(256 / 8, cek.len());
        }

        // Serde test
        let json = not_err!(serde_json::to_string(&encrypted_jwe));
        let deserialized_json: Compact = not_err!(serde_json::from_str(&json));
        assert_eq!(deserialized_json, encrypted_jwe);

        // Decrypt
        let decrypted_jwe = not_err!(Decrypted::<String, Empty>::decrypt(
            &encrypted_jwe,
            &key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A256GCM
        ));
        assert_eq!(jwe, decrypted_jwe);

        let decrypted_str = decrypted_jwe.payload;
        assert_eq!(decrypted_str, payload);
    }

    #[test]
    fn jwe_a256gcmkw_a256gcm_jws_round_trip() {
        // Construct the JWS
        let claims = crate::ClaimsSet::<Empty> {
            registered: crate::RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(crate::SingleOrMultiple::Single(not_err!(
                    FromStr::from_str("htts://acme-customer.com")
                ))),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: Default::default(),
        };
        let jws = jws::Decoded::new(
            From::from(jws::RegisteredHeader {
                algorithm: jwa::SignatureAlgorithm::HS256,
                ..Default::default()
            }),
            claims,
        );
        let jws = not_err!(jws.encode(&jws::Secret::Bytes("secret".to_string().into_bytes())));

        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                media_type: Some("JOSE".to_string()),
                content_type: Some("JOSE".to_string()),
                ..Default::default()
            }),
            jws.clone(),
        );
        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };

        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &options));

        {
            // Check that new header values are added
            let compact = encrypted_jwe.clone();
            let header: Header<Empty> = compact.deser_part(0).unwrap();
            assert!(header.cek_algorithm.nonce.is_some());
            assert!(header.cek_algorithm.tag.is_some());

            // Check that the encrypted key part is not empty
            let cek: Vec<u8> = compact.part_decoded(1).unwrap();
            assert_eq!(256 / 8, cek.len());
        }

        // Serde test
        let json = not_err!(serde_json::to_string(&encrypted_jwe));
        let deserialized_json: Compact = not_err!(serde_json::from_str(&json));
        assert_eq!(deserialized_json, encrypted_jwe);

        // Decrypt
        let decrypted_jwe = not_err!(Decrypted::decrypt(
            &encrypted_jwe,
            &key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A256GCM
        ));
        assert_eq!(jwe, decrypted_jwe);

        let decrypted_jws = decrypted_jwe.payload;
        assert_eq!(jws, decrypted_jws);
    }

    #[test]
    fn jwe_dir_aes256gcm_jws_round_trip() {
        // Construct the JWS
        let claims = crate::ClaimsSet::<Empty> {
            registered: crate::RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(crate::SingleOrMultiple::Single(not_err!(
                    FromStr::from_str("htts://acme-customer.com")
                ))),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: Default::default(),
        };
        let jws = jws::Decoded::new(
            From::from(jws::RegisteredHeader {
                algorithm: jwa::SignatureAlgorithm::HS256,
                ..Default::default()
            }),
            claims,
        );
        let jws = not_err!(jws.encode(&jws::Secret::Bytes("secret".to_string().into_bytes())));

        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: KeyManagementAlgorithm::DirectSymmetricKey,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                media_type: Some("JOSE".to_string()),
                content_type: Some("JOSE".to_string()),
                ..Default::default()
            }),
            jws.clone(),
        );
        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };

        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &options));

        {
            let compact = encrypted_jwe.clone();
            // Check that new header values are empty
            let header: Header<Empty> = compact.deser_part(0).unwrap();
            assert!(header.cek_algorithm.nonce.is_none());
            assert!(header.cek_algorithm.tag.is_none());

            // Check that the encrypted key part is empty
            let cek: Vec<u8> = compact.part_decoded(1).unwrap();
            assert!(cek.is_empty());
        }

        // Serde test
        let json = not_err!(serde_json::to_string(&encrypted_jwe));
        let deserialized_json: Compact = not_err!(serde_json::from_str(&json));
        assert_eq!(deserialized_json, encrypted_jwe);

        // Decrypt
        let decrypted_jwe = not_err!(Decrypted::decrypt(
            &encrypted_jwe,
            &key,
            KeyManagementAlgorithm::DirectSymmetricKey,
            ContentEncryptionAlgorithm::A256GCM
        ));
        assert_eq!(jwe, decrypted_jwe);

        let decrypted_jws = decrypted_jwe.payload;
        assert_eq!(jws, decrypted_jws);
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn decrypt_with_mismatch_cek_algorithm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );
        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };

        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &options));

        let _: Decrypted<Vec<u8>, Empty> = Decrypted::decrypt(
            &encrypted_jwe,
            &key,
            KeyManagementAlgorithm::A128GCMKW,
            ContentEncryptionAlgorithm::A256GCM,
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn decrypt_with_mismatch_enc_algorithm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );

        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };
        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &options));

        let _: Decrypted<Vec<u8>, Empty> = Decrypted::decrypt(
            &encrypted_jwe,
            &key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A128GCM,
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "PartsLengthError")]
    fn decrypt_with_incorrect_length() {
        let key = cek_oct_key(256 / 8);
        let invalid = Compact::decode("INVALID");
        let _ = Decrypted::<Empty, Empty>::decrypt(
            &invalid,
            &key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A128GCM,
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_nonce_for_aes256gcmkw() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );

        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };
        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &options));

        // Modify the JWE
        let mut header: Header<Empty> = encrypted_jwe.deser_part(0).unwrap();
        header.cek_algorithm.nonce = Some(vec![0; 96 / 8]);
        let s = format!(
            "{}.{}.{}.{}.{}",
            base64::encode_config(
                serde_json::to_string(&header).unwrap(),
                base64::URL_SAFE_NO_PAD
            ),
            encrypted_jwe.part(1).unwrap(),
            encrypted_jwe.part(2).unwrap(),
            encrypted_jwe.part(3).unwrap(),
            encrypted_jwe.part(4).unwrap()
        );

        let encrypted_jwe = Compact::decode(&s);
        let _: Decrypted<Vec<u8>, Empty> = Decrypted::decrypt(
            &encrypted_jwe,
            &key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A256GCM,
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_tag_for_aes256gcmkw() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );

        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };
        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &options));

        // Modify the JWE
        let mut header: Header<Empty> = encrypted_jwe.deser_part(0).unwrap();
        header.cek_algorithm.tag = Some(vec![0; 96 / 8]);
        let s = format!(
            "{}.{}.{}.{}.{}",
            base64::encode_config(
                serde_json::to_string(&header).unwrap(),
                base64::URL_SAFE_NO_PAD
            ),
            encrypted_jwe.part(1).unwrap(),
            encrypted_jwe.part(2).unwrap(),
            encrypted_jwe.part(3).unwrap(),
            encrypted_jwe.part(4).unwrap()
        );

        let encrypted_jwe = Compact::decode(&s);
        let _: Decrypted<Vec<u8>, Empty> = Decrypted::decrypt(
            &encrypted_jwe,
            &key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A256GCM,
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_tag_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );

        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };
        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &options));

        // Modify the JWE
        let s = format!(
            "{}.{}.{}.{}.{}",
            encrypted_jwe.part(0).unwrap(),
            encrypted_jwe.part(1).unwrap(),
            encrypted_jwe.part(2).unwrap(),
            encrypted_jwe.part(3).unwrap(),
            base64::encode_config(&[0], base64::URL_SAFE_NO_PAD),
        );

        let encrypted_jwe = Compact::decode(&s);
        let _: Decrypted<Vec<u8>, Empty> = Decrypted::decrypt(
            &encrypted_jwe,
            &key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A256GCM,
        )
        .unwrap();
    }

    /// This test modifies the header so the tag (aad for the AES GCM) included becomes incorrect
    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_modified_header_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );
        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };

        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &options));

        // Modify the JWE
        let mut header: Header<Empty> = encrypted_jwe.deser_part(0).unwrap();
        header.registered.media_type = Some("JOSE+JSON".to_string());
        let s = format!(
            "{}.{}.{}.{}.{}",
            base64::encode_config(
                serde_json::to_string(&header).unwrap(),
                base64::URL_SAFE_NO_PAD
            ),
            encrypted_jwe.part(1).unwrap(),
            encrypted_jwe.part(2).unwrap(),
            encrypted_jwe.part(3).unwrap(),
            encrypted_jwe.part(4).unwrap()
        );

        let encrypted_jwe = Compact::decode(&s);
        let _: Decrypted<Vec<u8>, Empty> = Decrypted::decrypt(
            &encrypted_jwe,
            &key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A256GCM,
        )
        .unwrap();
    }

    /// This test modifies the encrypted cek
    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_modified_encrypted_cek_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );

        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };
        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &options));

        // Modify the JWE
        let s = format!(
            "{}.{}.{}.{}.{}",
            encrypted_jwe.part(0).unwrap(),
            base64::encode_config(vec![0u8; 256 / 8], base64::URL_SAFE_NO_PAD),
            encrypted_jwe.part(2).unwrap(),
            encrypted_jwe.part(3).unwrap(),
            encrypted_jwe.part(4).unwrap()
        );

        let encrypted_jwe = Compact::decode(&s);
        let _: Decrypted<Vec<u8>, Empty> = Decrypted::decrypt(
            &encrypted_jwe,
            &key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A256GCM,
        )
        .unwrap();
    }

    /// This test modifies the encrypted payload
    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_modified_encrypted_payload_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );
        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };

        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &options));

        // Modify the JWE
        let s = format!(
            "{}.{}.{}.{}.{}",
            encrypted_jwe.part(0).unwrap(),
            encrypted_jwe.part(1).unwrap(),
            encrypted_jwe.part(2).unwrap(),
            base64::encode_config(vec![0u8; 32], base64::URL_SAFE_NO_PAD),
            encrypted_jwe.part(4).unwrap()
        );

        let encrypted_jwe = Compact::decode(&s);
        let _: Decrypted<Vec<u8>, Empty> = Decrypted::decrypt(
            &encrypted_jwe,
            &key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A256GCM,
        )
        .unwrap();
    }

    /// This test modifies the nonce
    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_modified_encrypted_nonce_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );
        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };

        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &options));

        // Modify the JWE
        let s = format!(
            "{}.{}.{}.{}.{}",
            encrypted_jwe.part(0).unwrap(),
            encrypted_jwe.part(1).unwrap(),
            base64::encode_config(vec![0u8; 96 / 8], base64::URL_SAFE_NO_PAD),
            encrypted_jwe.part(3).unwrap(),
            encrypted_jwe.part(4).unwrap()
        );

        let encrypted_jwe = Compact::decode(&s);
        let _: Decrypted<Vec<u8>, Empty> = Decrypted::decrypt(
            &encrypted_jwe,
            &key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A256GCM,
        )
        .unwrap();
    }
}
