//! JSON Web Algorithms
//!
//! Code for implementing JWA according to [RFC 7518](https://tools.ietf.org/html/rfc7518).
//!
//! Typically, you will not use these directly, but as part of a JWS or JWE.

use std::fmt;
use std::num::NonZeroU32;

use ::hmac::Hmac;
use aes::cipher::{Block, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cipher::block_padding::Pkcs7;
use cipher::BlockSizeUser;
use once_cell::sync::Lazy;
use ring::constant_time::verify_slices_are_equal;
use ring::rand::SystemRandom;
use ring::signature::KeyPair;
use ring::{aead, hmac, rand, signature};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::errors::Error;
use crate::jwe::CekAlgorithmHeader;
use crate::jwk;
use crate::jws::Secret;
use crate::Empty;

pub use ring::rand::SecureRandom;

/// AES GCM Tag Size, in bytes
const AES_GCM_TAG_SIZE: usize = 128 / 8;
/// AES GCM Nonce length, in bytes
const AES_GCM_NONCE_LENGTH: usize = 96 / 8;
/// AES CBC HMAC SHA Nonce length, in bytes
const AES_CBC_HMAC_SHA_NONCE_LENGTH: usize = 128 / 8;

/// A zeroed AES GCM Nonce EncryptionOptions
static AES_GCM_ZEROED_NONCE: Lazy<EncryptionOptions> = Lazy::new(|| EncryptionOptions::AES_GCM {
    nonce: vec![0; AES_GCM_NONCE_LENGTH],
});
/// A zeroed AES GCM Nonce EncryptionOptions
static AES_CBC_HMAC_SHA_ZEROED_NONCE: Lazy<EncryptionOptions> =
    Lazy::new(|| EncryptionOptions::AES_CBC_HMAC_SHA {
        nonce: vec![0; AES_CBC_HMAC_SHA_NONCE_LENGTH],
    });

/// Options to be passed in while performing an encryption operation, if required by the algorithm.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum EncryptionOptions {
    /// No options are required. Most algorithms do not require additional parameters
    None,
    /// Options for AES GCM encryption.
    AES_GCM {
        /// Initialization vector, or nonce for the AES GCM encryption. _MUST BE_ 96 bits long.
        ///
        /// AES GCM encryption operations should not reuse the nonce, or initialization vector.
        /// Users should keep track of previously used
        /// nonces and not reuse them. A simple way to keep track is to simply increment the nonce
        /// as a 96 bit counter.
        nonce: Vec<u8>,
    },
    /// Options for AES CBC HMAC SHA encryption.
    AES_CBC_HMAC_SHA {
        /// Initialization vector, or nonce for the AES CBC HMAC SHA encryption. _MUST BE_ 128 bits long.
        ///
        /// AES CBC HMAC SHA encryption operations should not reuse the nonce, or initialization vector.
        /// Users should keep track of previously used
        /// nonces and not reuse them. A simple way to keep track is to simply increment the nonce
        /// as a 128 bit counter.
        nonce: Vec<u8>,
    },
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
/// Algorithms described by [RFC 7518](https://tools.ietf.org/html/rfc7518).
/// This enum is serialized `untagged`.
#[serde(untagged)]
pub enum Algorithm {
    /// Algorithms meant for Digital signature or MACs
    /// See [RFC7518#3](https://tools.ietf.org/html/rfc7518#section-3)
    Signature(SignatureAlgorithm),
    /// Algorithms meant for key management. The algorithms are either meant to
    /// encrypt a content encryption key or determine the content encryption key.
    /// See [RFC7518#4](https://tools.ietf.org/html/rfc7518#section-4)
    KeyManagement(KeyManagementAlgorithm),
    /// Algorithms meant for content encryption.
    /// See [RFC7518#5](https://tools.ietf.org/html/rfc7518#section-5)
    ContentEncryption(ContentEncryptionAlgorithm),
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
/// The algorithms supported for digital signature and MACs, defined by
/// [RFC7518#3](https://tools.ietf.org/html/rfc7518#section-3).
pub enum SignatureAlgorithm {
    /// No encryption/signature is included for the JWT.
    /// During verification, the signature _MUST BE_ empty or verification  will fail.
    #[serde(rename = "none")]
    None,
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
    /// ECDSA using P-256 and SHA-256
    ES256,
    /// ECDSA using P-384 and SHA-384
    ES384,
    /// ECDSA using P-521 and SHA-512 --
    /// This variant is [unsupported](https://github.com/briansmith/ring/issues/268) and will probably never be.
    ES512,
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    /// The size of the salt value is the same size as the hash function output.
    PS256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    /// The size of the salt value is the same size as the hash function output.
    PS384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    /// The size of the salt value is the same size as the hash function output.
    PS512,
}

/// Algorithms for key management as defined in [RFC7518#4](https://tools.ietf.org/html/rfc7518#section-4)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum KeyManagementAlgorithm {
    /// RSAES-PKCS1-v1_5
    RSA1_5,
    /// RSAES OAEP using default parameters
    #[serde(rename = "RSA-OAEP")]
    RSA_OAEP,
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    #[serde(rename = "RSA-OAEP-256")]
    RSA_OAEP_256,
    /// AES Key Wrap using 128-bit key. _Unsupported_
    A128KW,
    /// AES Key Wrap using 192-bit key. _Unsupported_.
    /// This is [not supported](https://github.com/briansmith/ring/issues/112) by `ring`.
    A192KW,
    /// AES Key Wrap using 256-bit key. _Unsupported_
    A256KW,
    /// Direct use of a shared symmetric key
    #[serde(rename = "dir")]
    DirectSymmetricKey,
    /// ECDH-ES using Concat KDF
    #[serde(rename = "ECDH-ES")]
    ECDH_ES,
    /// ECDH-ES using Concat KDF and "A128KW" wrapping
    #[serde(rename = "ECDH-ES+A128KW")]
    ECDH_ES_A128KW,
    /// ECDH-ES using Concat KDF and "A192KW" wrapping
    #[serde(rename = "ECDH-ES+A192KW")]
    ECDH_ES_A192KW,
    /// ECDH-ES using Concat KDF and "A256KW" wrapping
    #[serde(rename = "ECDH-ES+A256KW")]
    ECDH_ES_A256KW,
    /// Key wrapping with AES GCM using 128-bit key alg
    A128GCMKW,
    /// Key wrapping with AES GCM using 192-bit key alg.
    /// This is [not supported](https://github.com/briansmith/ring/issues/112) by `ring`.
    A192GCMKW,
    /// Key wrapping with AES GCM using 256-bit key alg
    A256GCMKW,
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    #[serde(rename = "PBES2-HS256+A128KW")]
    PBES2_HS256_A128KW,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    #[serde(rename = "PBES2-HS384+A192KW")]
    PBES2_HS384_A192KW,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    #[serde(rename = "PBES2-HS512+A256KW")]
    PBES2_HS512_A256KW,
}

/// Algorithms for key management as defined in [RFC7518#4.7](https://tools.ietf.org/html/rfc7518#section-4.7)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum KeyManagementAlgorithmAESGCM {
    /// Key wrapping with AES GCM using 128-bit key alg
    A128GCMKW,
    /// Key wrapping with AES GCM using 192-bit key alg.
    /// This is [not supported](https://github.com/briansmith/ring/issues/112) by `ring`.
    A192GCMKW,
    /// Key wrapping with AES GCM using 256-bit key alg
    A256GCMKW,
}

/// Algorithms for key management as defined in [RFC7518#4.7](https://tools.ietf.org/html/rfc7518#section-4.7)
#[allow(non_camel_case_types)]
pub struct AESGCM {
    pub kma: KeyManagementAlgorithmAESGCM,
    pub iv: Vec<u8>,
    pub tag: Vec<u8>,
}

/// Algorithms for key management as defined in [RFC7518#4.8](https://tools.ietf.org/html/rfc7518#section-4.8)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum KeyManagementAlgorithmPBES2 {
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    #[serde(rename = "PBES2-HS256+A128KW")]
    PBES2_HS256_A128KW,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    #[serde(rename = "PBES2-HS384+A192KW")]
    PBES2_HS384_A192KW,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    #[serde(rename = "PBES2-HS512+A256KW")]
    PBES2_HS512_A256KW,
}

/// Algorithms for key management as defined in [RFC7518#4.8](https://tools.ietf.org/html/rfc7518#section-4.8)
#[allow(non_camel_case_types)]
pub struct PBES2 {
    pub kma: KeyManagementAlgorithmPBES2,
    pub salt: String,
    pub count: u32,
}

/// Describes the type of operations that the key management algorithm
/// supports with respect to a Content Encryption Key (CEK)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum KeyManagementAlgorithmType {
    /// Wraps a randomly generated CEK using a symmetric encryption algorithm
    SymmetricKeyWrapping,
    /// Encrypt a randomly generated CEK using an asymmetric encryption algorithm,
    AsymmetricKeyEncryption,
    /// A key agreement algorithm to pick a CEK
    DirectKeyAgreement,
    /// A key agreement algorithm used to pick a symmetric CEK and wrap the CEK with a symmetric encryption algorithm
    KeyAgreementWithKeyWrapping,
    /// A user defined symmetric shared key is the CEK
    DirectEncryption,
}

/// Algorithms meant for content encryption.
/// See [RFC7518#5](https://tools.ietf.org/html/rfc7518#section-5)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum ContentEncryptionAlgorithm {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm enc
    #[serde(rename = "A128CBC-HS256")]
    A128CBC_HS256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm enc
    #[serde(rename = "A192CBC-HS384")]
    A192CBC_HS384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm enc
    #[serde(rename = "A256CBC-HS512")]
    A256CBC_HS512,
    /// AES GCM using 128-bit key
    A128GCM,
    /// AES GCM using 192-bit key
    /// This is [not supported](https://github.com/briansmith/ring/issues/112) by `ring`.
    A192GCM,
    /// AES GCM using 256-bit key
    A256GCM,
}

/// The result returned from an encryption operation
// TODO: Might have to turn this into an enum
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct EncryptionResult {
    /// The initialization vector, or nonce used in the encryption
    pub nonce: Vec<u8>,
    /// The encrypted payload
    pub encrypted: Vec<u8>,
    /// The authentication tag
    pub tag: Vec<u8>,
    /// Additional authenticated data that is integrity protected but not encrypted
    pub additional_data: Vec<u8>,
}

impl Default for EncryptionOptions {
    fn default() -> Self {
        EncryptionOptions::None
    }
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        SignatureAlgorithm::HS256
    }
}

impl Default for KeyManagementAlgorithm {
    fn default() -> Self {
        KeyManagementAlgorithm::DirectSymmetricKey
    }
}

impl Default for ContentEncryptionAlgorithm {
    fn default() -> Self {
        ContentEncryptionAlgorithm::A128GCM
    }
}

impl EncryptionOptions {
    /// Description of the type of key
    pub fn description(&self) -> &'static str {
        match self {
            EncryptionOptions::None => "None",
            EncryptionOptions::AES_GCM { .. } => "AES GCM Nonce/Initialization Vector",
            EncryptionOptions::AES_CBC_HMAC_SHA { .. } => {
                "AES CBC HMAC SHA Nonce/Initialization Vector"
            }
        }
    }
}

impl fmt::Display for EncryptionOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl SignatureAlgorithm {
    /// Take some bytes and sign it according to the algorithm and secret provided.
    pub fn sign(self, data: &[u8], secret: &Secret) -> Result<Vec<u8>, Error> {
        use self::SignatureAlgorithm::*;

        match self {
            None => Self::sign_none(secret),
            HS256 | HS384 | HS512 => Self::sign_hmac(data, secret, self),
            RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => Self::sign_rsa(data, secret, self),
            ES256 | ES384 | ES512 => Self::sign_ecdsa(data, secret, self),
        }
    }

    /// Verify signature based on the algorithm and secret provided.
    pub fn verify(
        self,
        expected_signature: &[u8],
        data: &[u8],
        secret: &Secret,
    ) -> Result<(), Error> {
        use self::SignatureAlgorithm::*;

        match self {
            None => Self::verify_none(expected_signature, secret),
            HS256 | HS384 | HS512 => Self::verify_hmac(expected_signature, data, secret, self),
            RS256 | RS384 | RS512 | PS256 | PS384 | PS512 | ES256 | ES384 | ES512 => {
                Self::verify_public_key(expected_signature, data, secret, self)
            }
        }
    }

    /// Returns the type of operations the key is meant for
    fn sign_none(secret: &Secret) -> Result<Vec<u8>, Error> {
        match *secret {
            Secret::None => {}
            _ => Err("Invalid secret type. `None` should be provided".to_string())?,
        };
        Ok(vec![])
    }

    fn sign_hmac(
        data: &[u8],
        secret: &Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        let secret = match *secret {
            Secret::Bytes(ref secret) => secret,
            _ => Err("Invalid secret type. A byte array is required".to_string())?,
        };

        let algorithm = match algorithm {
            SignatureAlgorithm::HS256 => &hmac::HMAC_SHA256,
            SignatureAlgorithm::HS384 => &hmac::HMAC_SHA384,
            SignatureAlgorithm::HS512 => &hmac::HMAC_SHA512,
            _ => unreachable!("Should not happen"),
        };
        let key = hmac::Key::new(*algorithm, secret);
        Ok(hmac::sign(&key, data).as_ref().to_vec())
    }

    fn sign_rsa(
        data: &[u8],
        secret: &Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        let key_pair = match *secret {
            Secret::RsaKeyPair(ref key_pair) => key_pair,
            _ => Err("Invalid secret type. A RsaKeyPair is required".to_string())?,
        };

        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; key_pair.public_modulus_len()];
        let padding_algorithm: &dyn signature::RsaEncoding = match algorithm {
            SignatureAlgorithm::RS256 => &signature::RSA_PKCS1_SHA256,
            SignatureAlgorithm::RS384 => &signature::RSA_PKCS1_SHA384,
            SignatureAlgorithm::RS512 => &signature::RSA_PKCS1_SHA512,
            SignatureAlgorithm::PS256 => &signature::RSA_PSS_SHA256,
            SignatureAlgorithm::PS384 => &signature::RSA_PSS_SHA384,
            SignatureAlgorithm::PS512 => &signature::RSA_PSS_SHA512,
            _ => unreachable!("Should not happen"),
        };

        key_pair.sign(padding_algorithm, &rng, data, &mut signature)?;
        Ok(signature)
    }

    fn sign_ecdsa(
        data: &[u8],
        secret: &Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        let key_pair = match *secret {
            Secret::EcdsaKeyPair(ref key_pair) => key_pair,
            _ => Err("Invalid secret type. An EcdsaKeyPair is required".to_string())?,
        };
        if let SignatureAlgorithm::ES512 = algorithm {
            // See https://github.com/briansmith/ring/issues/268
            Err(Error::UnsupportedOperation)
        } else {
            let rng = rand::SystemRandom::new();
            let sig = key_pair.as_ref().sign(&rng, data)?;
            Ok(sig.as_ref().to_vec())
        }
    }

    fn verify_none(expected_signature: &[u8], secret: &Secret) -> Result<(), Error> {
        match *secret {
            Secret::None => {}
            _ => Err("Invalid secret type. `None` should be provided".to_string())?,
        };

        if expected_signature.is_empty() {
            Ok(())
        } else {
            Err(Error::UnspecifiedCryptographicError)
        }
    }

    fn verify_hmac(
        expected_signature: &[u8],
        data: &[u8],
        secret: &Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<(), Error> {
        let actual_signature = Self::sign_hmac(data, secret, algorithm)?;
        verify_slices_are_equal(expected_signature, actual_signature.as_ref())?;
        Ok(())
    }

    fn verify_public_key(
        expected_signature: &[u8],
        data: &[u8],
        secret: &Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<(), Error> {
        match *secret {
            Secret::PublicKey(ref public_key) => {
                let verification_algorithm: &dyn signature::VerificationAlgorithm = match algorithm
                {
                    SignatureAlgorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    SignatureAlgorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    SignatureAlgorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    SignatureAlgorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
                    SignatureAlgorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
                    SignatureAlgorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
                    SignatureAlgorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED,
                    SignatureAlgorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED,
                    SignatureAlgorithm::ES512 => Err(Error::UnsupportedOperation)?,
                    _ => unreachable!("Should not happen"),
                };

                let public_key = signature::UnparsedPublicKey::new(
                    verification_algorithm,
                    public_key.as_slice(),
                );
                public_key.verify(data, expected_signature)?;
                Ok(())
            }
            Secret::RsaKeyPair(ref keypair) => {
                let verification_algorithm: &dyn signature::VerificationAlgorithm = match algorithm
                {
                    SignatureAlgorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    SignatureAlgorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    SignatureAlgorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    SignatureAlgorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
                    SignatureAlgorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
                    SignatureAlgorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
                    _ => unreachable!("Should not happen"),
                };

                let public_key =
                    signature::UnparsedPublicKey::new(verification_algorithm, keypair.public_key());
                public_key.verify(data, expected_signature)?;
                Ok(())
            }
            Secret::RSAModulusExponent { ref n, ref e } => {
                let params = match algorithm {
                    SignatureAlgorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    SignatureAlgorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    SignatureAlgorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    SignatureAlgorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
                    SignatureAlgorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
                    SignatureAlgorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
                    _ => unreachable!("(n,e) secret with a non-rsa algorithm should not happen"),
                };

                let n_big_endian = n.to_bytes_be();
                let e_big_endian = e.to_bytes_be();
                let public_key = signature::RsaPublicKeyComponents {
                    n: n_big_endian,
                    e: e_big_endian,
                };
                public_key.verify(params, data, expected_signature)?;
                Ok(())
            }
            Secret::EcdsaKeyPair(ref keypair) => {
                let verification_algorithm: &dyn signature::VerificationAlgorithm = match algorithm
                {
                    SignatureAlgorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED,
                    SignatureAlgorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED,
                    SignatureAlgorithm::ES512 => Err(Error::UnsupportedOperation)?,
                    _ => unreachable!("Should not happen"),
                };

                let public_key =
                    signature::UnparsedPublicKey::new(verification_algorithm, keypair.public_key());
                public_key.verify(data, expected_signature)?;
                Ok(())
            }
            _ => unreachable!("This is a private method and should not be called erroneously."),
        }
    }
}

impl KeyManagementAlgorithm {
    /// Returns the type of operations that the algorithm is intended to support
    pub fn algorithm_type(self) -> KeyManagementAlgorithmType {
        use self::KeyManagementAlgorithm::*;

        match self {
            A128KW | A192KW | A256KW | A128GCMKW | A192GCMKW | A256GCMKW | PBES2_HS256_A128KW
            | PBES2_HS384_A192KW | PBES2_HS512_A256KW => {
                KeyManagementAlgorithmType::SymmetricKeyWrapping
            }
            RSA1_5 | RSA_OAEP | RSA_OAEP_256 => KeyManagementAlgorithmType::AsymmetricKeyEncryption,
            DirectSymmetricKey => KeyManagementAlgorithmType::DirectEncryption,
            ECDH_ES => KeyManagementAlgorithmType::DirectKeyAgreement,
            ECDH_ES_A128KW | ECDH_ES_A192KW | ECDH_ES_A256KW => {
                KeyManagementAlgorithmType::KeyAgreementWithKeyWrapping
            }
        }
    }

    /// Return the Content Encryption Key (CEK) based on the key management algorithm
    ///
    /// If the algorithm is `dir` or `DirectSymmetricKey`, the key provided is the CEK.
    /// Otherwise, the appropriate algorithm will be used to derive or generate the required CEK
    /// using the provided key.
    pub fn cek<T>(
        self,
        content_alg: ContentEncryptionAlgorithm,
        key: &jwk::JWK<T>,
    ) -> Result<jwk::JWK<Empty>, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        use self::KeyManagementAlgorithm::{DirectSymmetricKey, A128GCMKW, A256GCMKW};

        match self {
            DirectSymmetricKey => Self::cek_direct(key),
            A128GCMKW | A256GCMKW => Self::cek_aes_gcm(content_alg),
            // PBES2_HS256_A128KW | PBES2_HS384_A192KW | PBES2_HS512_A256KW => Self::cek_pbes2(key),
            _ => Err(Error::UnsupportedOperation),
        }
    }

    fn cek_direct<T>(key: &jwk::JWK<T>) -> Result<jwk::JWK<Empty>, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        match key.key_type() {
            jwk::KeyType::Octet => Ok(key.clone_without_additional()),
            others => Err(unexpected_key_type_error!(jwk::KeyType::Octet, others)),
        }
    }

    // fn cek_pbes2<T>(self, key: &jwk::JWK<T>) -> Result<jwk::JWK<Empty>, Error>
    // where
    //     T: Serialize + DeserializeOwned,
    // {
    //     let key = match key.key_type() {
    //         jwk::KeyType::Octet => key.clone_without_additional(),
    //         others => Err(unexpected_key_type_error!(jwk::KeyType::Octet, others)),
    //     };

    // }

    fn cek_aes_gcm(content_alg: ContentEncryptionAlgorithm) -> Result<jwk::JWK<Empty>, Error> {
        let key = content_alg.generate_key()?;
        Ok(jwk::JWK {
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                value: key,
                key_type: Default::default(),
            }),
            common: jwk::CommonParameters {
                public_key_use: Some(jwk::PublicKeyUse::Encryption),
                algorithm: Some(Algorithm::ContentEncryption(content_alg)),
                ..Default::default()
            },
            additional: Default::default(),
        })
    }

    /// Encrypt or wrap a Content Encryption Key with the provided algorithm
    pub fn wrap_key<T: Serialize + DeserializeOwned>(
        self,
        payload: &[u8],
        key: &jwk::JWK<T>,
        header: &mut CekAlgorithmHeader,
    ) -> Result<Vec<u8>, Error> {
        use self::KeyManagementAlgorithm::{
            DirectSymmetricKey, A128GCMKW, A192GCMKW, A256GCMKW, PBES2_HS256_A128KW,
            PBES2_HS384_A192KW, PBES2_HS512_A256KW,
        };

        match self {
            A128GCMKW | A192GCMKW | A256GCMKW => {
                let nonce = header.nonce.as_deref().ok_or(Error::UnsupportedOperation)?;
                let encrypted = self.aes_gcm_encrypt(payload, key.algorithm.octet_key()?, nonce)?;
                header.tag = Some(encrypted.tag);
                Ok(encrypted.encrypted)
            }
            PBES2_HS256_A128KW => {
                let key = key.algorithm.octet_key()?;
                PBES2 {
                    kma: KeyManagementAlgorithmPBES2::PBES2_HS256_A128KW,
                    salt: header.salt.clone().ok_or(Error::UnsupportedOperation)?,
                    count: header.count.unwrap_or_default(),
                }
                .encrypt(payload, key)
            }
            PBES2_HS384_A192KW => {
                let key = key.algorithm.octet_key()?;
                PBES2 {
                    kma: KeyManagementAlgorithmPBES2::PBES2_HS384_A192KW,
                    salt: header.salt.take().unwrap_or_default(),
                    count: header.count.take().unwrap_or_default(),
                }
                .encrypt(payload, key)
            }
            PBES2_HS512_A256KW => {
                let key = key.algorithm.octet_key()?;
                PBES2 {
                    kma: KeyManagementAlgorithmPBES2::PBES2_HS512_A256KW,
                    salt: header.salt.take().unwrap_or_default(),
                    count: header.count.take().unwrap_or_default(),
                }
                .encrypt(payload, key)
            }
            DirectSymmetricKey => Ok(Vec::new()),
            _ => Err(Error::UnsupportedOperation),
        }
    }

    /// Decrypt or unwrap a CEK with the provided algorithm
    pub fn unwrap_key<T: Serialize + DeserializeOwned>(
        self,
        encrypted: &[u8],
        header: &mut CekAlgorithmHeader,
        key: &jwk::JWK<T>,
    ) -> Result<jwk::JWK<Empty>, Error> {
        use self::KeyManagementAlgorithm::{
            DirectSymmetricKey, A128GCMKW, A192GCMKW, A256GCMKW, PBES2_HS256_A128KW,
            PBES2_HS384_A192KW, PBES2_HS512_A256KW,
        };

        match self {
            A128GCMKW | A192GCMKW | A256GCMKW => {
                let key = key.algorithm.octet_key()?;

                self.aes_gcm_decrypt(
                    &EncryptionResult {
                        encrypted: encrypted.to_vec(),
                        nonce: header.nonce.take().unwrap_or_default(),
                        tag: header.tag.take().unwrap_or_default(),
                        ..Default::default()
                    },
                    key,
                )
            }
            PBES2_HS256_A128KW => {
                let key = key.algorithm.octet_key()?;
                PBES2 {
                    kma: KeyManagementAlgorithmPBES2::PBES2_HS256_A128KW,
                    salt: header.salt.take().unwrap_or_default(),
                    count: header.count.take().unwrap_or_default(),
                }
                .decrypt(encrypted, key)
            }
            PBES2_HS384_A192KW => {
                let key = key.algorithm.octet_key()?;
                PBES2 {
                    kma: KeyManagementAlgorithmPBES2::PBES2_HS384_A192KW,
                    salt: header.salt.take().unwrap_or_default(),
                    count: header.count.take().unwrap_or_default(),
                }
                .decrypt(encrypted, key)
            }
            PBES2_HS512_A256KW => {
                let key = key.algorithm.octet_key()?;
                PBES2 {
                    kma: KeyManagementAlgorithmPBES2::PBES2_HS512_A256KW,
                    salt: header.salt.take().unwrap_or_default(),
                    count: header.count.take().unwrap_or_default(),
                }
                .decrypt(encrypted, key)
            }
            DirectSymmetricKey => Ok(key.clone_without_additional()),
            _ => Err(Error::UnsupportedOperation),
        }
    }

    fn aes_gcm_encrypt(
        self,
        payload: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<EncryptionResult, Error> {
        use self::KeyManagementAlgorithm::{A128GCMKW, A256GCMKW};

        let algorithm = match self {
            A128GCMKW => &aead::AES_128_GCM,
            A256GCMKW => &aead::AES_256_GCM,
            _ => Err(Error::UnsupportedOperation)?,
        };

        aes_gcm_encrypt(algorithm, payload, nonce, &[], key)
    }

    fn aes_gcm_decrypt(
        self,
        encrypted: &EncryptionResult,
        key: &[u8],
    ) -> Result<jwk::JWK<Empty>, Error> {
        use self::KeyManagementAlgorithm::{A128GCMKW, A256GCMKW};

        let algorithm = match self {
            A128GCMKW => &aead::AES_128_GCM,
            A256GCMKW => &aead::AES_256_GCM,
            _ => Err(Error::UnsupportedOperation)?,
        };

        let cek = aes_gcm_decrypt(algorithm, encrypted, key)?;
        Ok(jwk::JWK {
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                value: cek,
                key_type: Default::default(),
            }),
            common: jwk::CommonParameters {
                public_key_use: Some(jwk::PublicKeyUse::Encryption),
                algorithm: None,
                ..Default::default()
            },
            additional: Default::default(),
        })
    }
}

impl PBES2 {
    fn encrypt(self, payload: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
        use KeyManagementAlgorithmPBES2::{
            PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW,
        };

        use ring::pbkdf2;
        let alg = match self.kma {
            PBES2_HS256_A128KW => pbkdf2::PBKDF2_HMAC_SHA256,
            PBES2_HS384_A192KW => pbkdf2::PBKDF2_HMAC_SHA384,
            PBES2_HS512_A256KW => pbkdf2::PBKDF2_HMAC_SHA512,
        };
        let len = match self.kma {
            PBES2_HS256_A128KW => 128 / 8,
            PBES2_HS384_A192KW => 192 / 8,
            PBES2_HS512_A256KW => 256 / 8,
        };
        let count = NonZeroU32::new(self.count).ok_or(Error::UnspecifiedCryptographicError)?;

        // compute salt
        let mut salt = match self.kma {
            PBES2_HS256_A128KW => b"PBES2-HS256+A128KW".to_vec(),
            PBES2_HS384_A192KW => b"PBES2-HS384+A192KW".to_vec(),
            PBES2_HS512_A256KW => b"PBES2-HS512+A256KW".to_vec(),
        };
        salt.push(0);
        base64::decode_config_buf(self.salt, base64::URL_SAFE_NO_PAD, &mut salt)?;

        let mut dk = [0; 32];
        pbkdf2::derive(alg, count, &salt, key, &mut dk[..len]);

        let len = (payload.len() + 7) / 8;
        let mut out = vec![0; len * 8 + 8];
        out[8..][..payload.len()].copy_from_slice(payload);

        match self.kma {
            PBES2_HS256_A128KW => block_cipher_key_wrap::<aes::Aes128Enc>(&dk[..16], &mut out)?,
            PBES2_HS384_A192KW => block_cipher_key_wrap::<aes::Aes192Enc>(&dk[..24], &mut out)?,
            PBES2_HS512_A256KW => block_cipher_key_wrap::<aes::Aes256Enc>(&dk, &mut out)?,
        }

        Ok(out)
    }

    fn decrypt(self, encrypted: &[u8], key: &[u8]) -> Result<jwk::JWK<Empty>, Error> {
        use KeyManagementAlgorithmPBES2::{
            PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW,
        };

        use ring::pbkdf2;
        let alg = match self.kma {
            PBES2_HS256_A128KW => pbkdf2::PBKDF2_HMAC_SHA256,
            PBES2_HS384_A192KW => pbkdf2::PBKDF2_HMAC_SHA384,
            PBES2_HS512_A256KW => pbkdf2::PBKDF2_HMAC_SHA512,
        };
        let len = match self.kma {
            PBES2_HS256_A128KW => 128 / 8,
            PBES2_HS384_A192KW => 192 / 8,
            PBES2_HS512_A256KW => 256 / 8,
        };
        let count = NonZeroU32::new(self.count).ok_or(Error::UnspecifiedCryptographicError)?;

        // compute salt
        let mut salt = match self.kma {
            PBES2_HS256_A128KW => b"PBES2-HS256+A128KW".to_vec(),
            PBES2_HS384_A192KW => b"PBES2-HS384+A192KW".to_vec(),
            PBES2_HS512_A256KW => b"PBES2-HS512+A256KW".to_vec(),
        };
        salt.push(0);
        base64::decode_config_buf(self.salt, base64::URL_SAFE_NO_PAD, &mut salt)?;

        let mut dk = [0; 32];
        pbkdf2::derive(alg, count, &salt, key, &mut dk[..len]);

        let len = (encrypted.len() + 7) / 8;
        let mut out = vec![0; len * 8 + 8];
        out[8..][..encrypted.len()].copy_from_slice(encrypted);

        match self.kma {
            PBES2_HS256_A128KW => block_cipher_key_unwrap::<aes::Aes128Dec>(&dk[..16], &mut out)?,
            PBES2_HS384_A192KW => block_cipher_key_unwrap::<aes::Aes192Dec>(&dk[..24], &mut out)?,
            PBES2_HS512_A256KW => block_cipher_key_unwrap::<aes::Aes256Dec>(&dk, &mut out)?,
        }

        Ok(jwk::JWK {
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                value: out,
                key_type: Default::default(),
            }),
            common: jwk::CommonParameters {
                public_key_use: Some(jwk::PublicKeyUse::Encryption),
                algorithm: None,
                ..Default::default()
            },
            additional: Default::default(),
        })
    }
}

const AES_KW_IV: u64 = 0xA6A6A6A6A6A6A6A6_u64;
/// AES key wrap in-place (https://www.rfc-editor.org/rfc/rfc3394#section-2.2.1)
///
/// Implementation is intended for AES128/AES192/AES256 and will likely fail on any other ciphers
fn block_cipher_key_wrap<T: cipher::KeyInit + BlockSizeUser + BlockEncryptMut + Clone>(
    key: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let cipher = T::new_from_slice(key)?;
    let block_size = T::block_size();

    let n = out.len() / 8 - 1;

    let mut a = AES_KW_IV;
    for j in 0..6 {
        for i in 1..=n {
            let ri = &mut out[i * 8..i * 8 + 8];

            // A | R[i]
            let mut input = [0; 32];
            input[..8].copy_from_slice(&a.to_be_bytes());
            input[8..16].copy_from_slice(ri);

            let mut out2 = [0u64; 4];
            let out_block = bytemuck::cast_slice_mut(&mut out2);

            // B = AES(K, A | R[i])
            let in_block = Block::<T>::from_slice(&input[..block_size]);
            let out_block = Block::<T>::from_mut_slice(&mut out_block[..block_size]);
            cipher.clone().encrypt_block_b2b_mut(in_block, out_block);

            // A = MSB(64, B) ^ t where t = (n*j)+i
            let t = n * j + i;
            a = out2[0].to_be() ^ t as u64;

            // R[i] = LSB(64, B)
            let lsb = block_size / 8;
            let lsb = lsb - 1..lsb;
            ri.copy_from_slice(bytemuck::cast_slice(&out2[lsb]))
        }
    }
    // Set C[0] = A
    out[..8].copy_from_slice(&a.to_be_bytes());
    Ok(())
}

/// AES key unwrap in-place (https://www.rfc-editor.org/rfc/rfc3394#section-2.2.2)
///
/// Implementation is intended for AES128/AES192/AES256 and will likely fail on any other ciphers
fn block_cipher_key_unwrap<T: cipher::KeyInit + BlockSizeUser + BlockDecryptMut + Clone>(
    key: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let cipher = T::new_from_slice(key)?;
    let block_size = T::block_size();

    let n = out.len() / 8 - 1;

    let mut a = u64::from_be_bytes(out[..8].try_into().unwrap());
    for j in (0..6).rev() {
        for i in (1..=n).rev() {
            let ri = &mut out[i * 8..i * 8 + 8];

            // (A ^ t) | R[i] where t = (n*j)+i
            let mut input = [0; 32];
            let t = n * j + i;
            input[..8].copy_from_slice(&(a ^ t as u64).to_be_bytes());
            input[8..16].copy_from_slice(ri);

            let mut out2 = [0u64; 4];
            let out_block = bytemuck::cast_slice_mut(&mut out2);

            // B = AES-1(K, (A ^ t) | R[i])
            let in_block = Block::<T>::from_slice(&input[..block_size]);
            let out_block2 = Block::<T>::from_mut_slice(&mut out_block[..block_size]);
            cipher.clone().decrypt_block_b2b_mut(in_block, out_block2);

            // A = MSB(64, B)
            a = out2[0].to_be();

            // R[i] = LSB(64, B)
            let lsb = block_size / 8;
            let lsb = lsb - 1..lsb;
            ri.copy_from_slice(bytemuck::cast_slice(&out2[lsb]))
        }
    }
    if a != AES_KW_IV {
        return Err(Error::UnspecifiedCryptographicError);
    }
    Ok(())
}

impl ContentEncryptionAlgorithm {
    /// Convenience function to generate a new random key with the required length
    pub fn generate_key(self) -> Result<Vec<u8>, Error> {
        use self::ContentEncryptionAlgorithm::{A128GCM, A256GCM};

        let length: usize = match self {
            A128GCM => 128 / 8,
            A256GCM => 256 / 8,
            _ => Err(Error::UnsupportedOperation)?,
        };

        let mut key: Vec<u8> = vec![0; length];
        SystemRandom::new().fill(&mut key)?;
        Ok(key)
    }

    /// Encrypt some payload with the provided algorith
    pub fn encrypt<T: Serialize + DeserializeOwned>(
        self,
        payload: &[u8],
        aad: &[u8],
        key: &jwk::JWK<T>,
        options: &EncryptionOptions,
    ) -> Result<EncryptionResult, Error> {
        use self::ContentEncryptionAlgorithm::{
            A128CBC_HS256, A128GCM, A192CBC_HS384, A192GCM, A256CBC_HS512, A256GCM,
        };

        match self {
            A128GCM | A192GCM | A256GCM => {
                self.aes_gcm_encrypt(payload, aad, key.algorithm.octet_key()?, options)
            }
            A128CBC_HS256 | A192CBC_HS384 | A256CBC_HS512 => {
                self.aes_cbc_encrypt(payload, aad, key, options)
            }
        }
    }

    /// Decrypt some payload with the provided algorith,
    pub fn decrypt<T: Serialize + DeserializeOwned>(
        self,
        encrypted: &EncryptionResult,
        key: &jwk::JWK<T>,
    ) -> Result<Vec<u8>, Error> {
        use self::ContentEncryptionAlgorithm::{
            A128CBC_HS256, A128GCM, A192CBC_HS384, A192GCM, A256CBC_HS512, A256GCM,
        };

        match self {
            A128GCM | A192GCM | A256GCM => self.aes_gcm_decrypt(encrypted, key.octet_key()?),
            A128CBC_HS256 | A192CBC_HS384 | A256CBC_HS512 => self.aes_cbc_decrypt(encrypted, key),
        }
    }

    /// Generate a new random `EncryptionOptions` based on the algorithm
    pub(crate) fn random_encryption_options(self) -> Result<EncryptionOptions, Error> {
        use self::ContentEncryptionAlgorithm::{
            A128CBC_HS256, A128GCM, A192CBC_HS384, A192GCM, A256CBC_HS512, A256GCM,
        };
        match self {
            A128GCM | A192GCM | A256GCM => Ok(EncryptionOptions::AES_GCM {
                nonce: random_aes_gcm_nonce()?,
            }),
            A128CBC_HS256 | A192CBC_HS384 | A256CBC_HS512 => {
                Ok(EncryptionOptions::AES_CBC_HMAC_SHA {
                    nonce: random_aes_cbc_nonce()?,
                })
            }
        }
    }

    fn aes_gcm_encrypt(
        self,
        payload: &[u8],
        aad: &[u8],
        key: &[u8],
        options: &EncryptionOptions,
    ) -> Result<EncryptionResult, Error> {
        use self::ContentEncryptionAlgorithm::{A128GCM, A256GCM};

        let algorithm = match self {
            A128GCM => &aead::AES_128_GCM,
            A256GCM => &aead::AES_256_GCM,
            _ => Err(Error::UnsupportedOperation)?,
        };

        let nonce = match *options {
            EncryptionOptions::AES_GCM { ref nonce } => Ok(nonce),
            ref others => Err(unexpected_encryption_options_error!(
                AES_GCM_ZEROED_NONCE,
                others
            )),
        }?;
        // FIXME: Should we check the nonce length here or leave it to ring?

        aes_gcm_encrypt(algorithm, payload, nonce.as_slice(), aad, key)
    }

    fn aes_gcm_decrypt(self, encrypted: &EncryptionResult, key: &[u8]) -> Result<Vec<u8>, Error> {
        use self::ContentEncryptionAlgorithm::{A128GCM, A256GCM};

        let algorithm = match self {
            A128GCM => &aead::AES_128_GCM,
            A256GCM => &aead::AES_256_GCM,
            _ => Err(Error::UnsupportedOperation)?,
        };
        aes_gcm_decrypt(algorithm, encrypted, key)
    }

    fn aes_cbc_encrypt<T: Serialize + DeserializeOwned>(
        self,
        payload: &[u8],
        aad: &[u8],
        key: &jwk::JWK<T>,
        options: &EncryptionOptions,
    ) -> Result<EncryptionResult, Error> {
        use self::ContentEncryptionAlgorithm::{A128CBC_HS256, A192CBC_HS384, A256CBC_HS512};

        let algorithm = match self {
            A128CBC_HS256 => AES_CBC_HMAC_SHA::A128CBC_HS256,
            A192CBC_HS384 => AES_CBC_HMAC_SHA::A192CBC_HS384,
            A256CBC_HS512 => AES_CBC_HMAC_SHA::A256CBC_HS512,
            _ => Err(Error::UnsupportedOperation)?,
        };

        let nonce = match *options {
            EncryptionOptions::AES_CBC_HMAC_SHA { ref nonce } => Ok(nonce),
            ref others => Err(unexpected_encryption_options_error!(
                AES_CBC_HMAC_SHA_ZEROED_NONCE,
                others
            )),
        }?;

        let key = key.algorithm.octet_key()?;
        aes_cbc_sha2_encrypt(algorithm, payload, nonce.as_slice(), aad, key)
    }

    fn aes_cbc_decrypt<T: Serialize + DeserializeOwned>(
        self,
        encrypted: &EncryptionResult,
        key: &jwk::JWK<T>,
    ) -> Result<Vec<u8>, Error> {
        use self::ContentEncryptionAlgorithm::{A128CBC_HS256, A192CBC_HS384, A256CBC_HS512};

        let algorithm = match self {
            A128CBC_HS256 => AES_CBC_HMAC_SHA::A128CBC_HS256,
            A192CBC_HS384 => AES_CBC_HMAC_SHA::A192CBC_HS384,
            A256CBC_HS512 => AES_CBC_HMAC_SHA::A256CBC_HS512,
            _ => Err(Error::UnsupportedOperation)?,
        };
        let key = key.algorithm.octet_key()?;
        aes_cbc_sha2_decrypt(algorithm, encrypted, key)
    }
}

/// Encrypt a payload with AES GCM
fn aes_gcm_encrypt(
    algorithm: &'static aead::Algorithm,
    payload: &[u8],
    nonce: &[u8],
    aad: &[u8],
    key: &[u8],
) -> Result<EncryptionResult, Error> {
    let key = aead::UnboundKey::new(algorithm, key)?;
    let sealing_key = aead::LessSafeKey::new(key);

    let mut in_out: Vec<u8> = payload.to_vec();
    let tag = sealing_key.seal_in_place_separate_tag(
        aead::Nonce::try_assume_unique_for_key(nonce)?,
        aead::Aad::from(aad),
        &mut in_out,
    )?;

    Ok(EncryptionResult {
        nonce: nonce.to_vec(),
        encrypted: in_out,
        tag: tag.as_ref().to_vec(),
        additional_data: aad.to_vec(),
    })
}

/// Decrypts a payload with AES GCM
fn aes_gcm_decrypt(
    algorithm: &'static aead::Algorithm,
    encrypted: &EncryptionResult,
    key: &[u8],
) -> Result<Vec<u8>, Error> {
    // JWA needs a 128 bit tag length. We need to assert that the algorithm has 128 bit tag length
    assert_eq!(algorithm.tag_len(), AES_GCM_TAG_SIZE);
    // Also the nonce (or initialization vector) needs to be 96 bits
    assert_eq!(algorithm.nonce_len(), AES_GCM_NONCE_LENGTH);

    let key = aead::UnboundKey::new(algorithm, key)?;
    let opening_key = aead::LessSafeKey::new(key);

    let mut in_out = encrypted.encrypted.clone();
    in_out.append(&mut encrypted.tag.clone());

    let nonce = aead::Nonce::try_assume_unique_for_key(&encrypted.nonce)?;
    let plaintext = opening_key.open_in_place(
        nonce,
        aead::Aad::from(&encrypted.additional_data),
        &mut in_out,
    )?;
    Ok(plaintext.to_vec())
}

#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
enum AES_CBC_HMAC_SHA {
    /// aes cbc mode
    A128CBC_HS256,
    /// aes cbc mode
    A192CBC_HS384,
    /// aes cbc mode
    A256CBC_HS512,
}

impl AES_CBC_HMAC_SHA {
    fn key_len(self) -> usize {
        match self {
            Self::A128CBC_HS256 => 16,
            Self::A192CBC_HS384 => 24,
            Self::A256CBC_HS512 => 32,
        }
    }
    fn hmac(self, key: &[u8], parts: [&[u8]; 4]) -> Result<Vec<u8>, ::digest::InvalidLength> {
        use ::hmac::Mac;
        let len = self.key_len();
        Ok(match self {
            Self::A128CBC_HS256 => {
                let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key)?;
                parts.into_iter().for_each(|c| mac.update(c));
                mac.finalize().into_bytes()[..len].to_vec()
            }
            Self::A192CBC_HS384 => {
                let mut mac = Hmac::<sha2::Sha384>::new_from_slice(key)?;
                parts.into_iter().for_each(|c| mac.update(c));
                mac.finalize().into_bytes()[..len].to_vec()
            }
            Self::A256CBC_HS512 => {
                let mut mac = Hmac::<sha2::Sha512>::new_from_slice(key)?;
                parts.into_iter().for_each(|c| mac.update(c));
                mac.finalize().into_bytes()[..len].to_vec()
            }
        })
    }
    fn hmac_validate(self, key: &[u8], parts: [&[u8]; 4], tag: &[u8]) -> Result<(), Error> {
        use ::hmac::Mac;
        match self {
            Self::A128CBC_HS256 => {
                let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key)?;
                parts.into_iter().for_each(|c| mac.update(c));
                mac.verify_truncated_left(tag)?
            }
            Self::A192CBC_HS384 => {
                let mut mac = Hmac::<sha2::Sha384>::new_from_slice(key)?;
                parts.into_iter().for_each(|c| mac.update(c));
                mac.verify_truncated_left(tag)?
            }
            Self::A256CBC_HS512 => {
                let mut mac = Hmac::<sha2::Sha512>::new_from_slice(key)?;
                parts.into_iter().for_each(|c| mac.update(c));
                mac.verify_truncated_left(tag)?
            }
        }
        Ok(())
    }
}

/// Encrypt a payload with AES GCM
fn aes_cbc_sha2_encrypt(
    alg: AES_CBC_HMAC_SHA,
    payload: &[u8],
    nonce: &[u8],
    aad: &[u8],
    key: &[u8],
) -> Result<EncryptionResult, Error> {
    use AES_CBC_HMAC_SHA::{A128CBC_HS256, A192CBC_HS384, A256CBC_HS512};

    let len = alg.key_len();
    if key.len() != len * 2 {
        return Err(Error::UnspecifiedCryptographicError);
    }

    let (mac_key, enc_key) = key.split_at(len);

    // encrypt the payload using aes-cbc
    let encrypted = match alg {
        A128CBC_HS256 => cbc::Encryptor::<aes::Aes128>::new_from_slices(enc_key, nonce)?
            .encrypt_padded_vec_mut::<Pkcs7>(payload),
        A192CBC_HS384 => cbc::Encryptor::<aes::Aes192>::new_from_slices(enc_key, nonce)?
            .encrypt_padded_vec_mut::<Pkcs7>(payload),
        A256CBC_HS512 => cbc::Encryptor::<aes::Aes256>::new_from_slices(enc_key, nonce)?
            .encrypt_padded_vec_mut::<Pkcs7>(payload),
    };

    // compute the hmac
    let al = (aad.len() as u64 * 8).to_be_bytes();
    let parts = [aad, nonce, encrypted.as_slice(), al.as_slice()];

    let tag = alg.hmac(mac_key, parts)?;

    Ok(EncryptionResult {
        nonce: nonce.to_vec(),
        encrypted,
        tag,
        additional_data: aad.to_vec(),
    })
}

/// Decrypts a payload with AES GCM
fn aes_cbc_sha2_decrypt(
    alg: AES_CBC_HMAC_SHA,
    encrypted: &EncryptionResult,
    key: &[u8],
) -> Result<Vec<u8>, Error> {
    use AES_CBC_HMAC_SHA::{A128CBC_HS256, A192CBC_HS384, A256CBC_HS512};

    let EncryptionResult {
        nonce,
        encrypted,
        tag,
        additional_data: aad,
    } = encrypted;

    let len = match alg {
        A128CBC_HS256 => 16,
        A192CBC_HS384 => 24,
        A256CBC_HS512 => 32,
    };

    if key.len() != len * 2 {
        return Err(Error::UnspecifiedCryptographicError);
    }
    let (mac_key, enc_key) = key.split_at(len);

    // compute the hmac
    let al = (aad.len() as u64 * 8).to_be_bytes();
    let parts = [
        aad.as_slice(),
        nonce.as_slice(),
        encrypted.as_slice(),
        al.as_slice(),
    ];

    alg.hmac_validate(mac_key, parts, tag)?;

    let decrypted = match alg {
        A128CBC_HS256 => cbc::Decryptor::<aes::Aes128>::new_from_slices(enc_key, nonce)?
            .decrypt_padded_vec_mut::<Pkcs7>(encrypted)?,
        A192CBC_HS384 => cbc::Decryptor::<aes::Aes192>::new_from_slices(enc_key, nonce)?
            .decrypt_padded_vec_mut::<Pkcs7>(encrypted)?,
        A256CBC_HS512 => cbc::Decryptor::<aes::Aes256>::new_from_slices(enc_key, nonce)?
            .decrypt_padded_vec_mut::<Pkcs7>(encrypted)?,
    };
    Ok(decrypted)
}

pub(crate) fn random_aes_gcm_nonce() -> Result<Vec<u8>, Error> {
    let mut nonce: Vec<u8> = vec![0; AES_GCM_NONCE_LENGTH];
    SystemRandom::new().fill(&mut nonce)?;
    Ok(nonce)
}
pub(crate) fn random_aes_cbc_nonce() -> Result<Vec<u8>, Error> {
    let mut nonce: Vec<u8> = vec![0; AES_CBC_HMAC_SHA_NONCE_LENGTH];
    SystemRandom::new().fill(&mut nonce)?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use ring::constant_time::verify_slices_are_equal;

    use super::*;
    use crate::jwa;

    #[test]
    fn sign_and_verify_none() {
        let expected_signature: Vec<u8> = vec![];
        let actual_signature = not_err!(
            SignatureAlgorithm::None.sign("payload".to_string().as_bytes(), &Secret::None,)
        );
        assert_eq!(expected_signature, actual_signature);

        not_err!(SignatureAlgorithm::None.verify(
            vec![].as_slice(),
            "payload".to_string().as_bytes(),
            &Secret::None
        ));
    }

    #[test]
    fn sign_and_verify_hs256() {
        let expected_base64 = "uC_LeRrOxXhZuYm0MKgmSIzi5Hn9-SMmvQoug3WkK6Q";
        let expected_bytes: Vec<u8> = not_err!(base64::decode_config(
            &expected_base64,
            base64::URL_SAFE_NO_PAD
        ));

        let actual_signature = not_err!(SignatureAlgorithm::HS256.sign(
            "payload".to_string().as_bytes(),
            &Secret::bytes_from_str("secret"),
        ));
        assert_eq!(
            &*base64::encode_config(actual_signature, base64::URL_SAFE_NO_PAD),
            expected_base64
        );

        not_err!(SignatureAlgorithm::HS256.verify(
            expected_bytes.as_slice(),
            "payload".to_string().as_bytes(),
            &Secret::bytes_from_str("secret"),
        ));
    }

    /// To generate the signature, use
    ///
    /// ```sh
    /// echo -n "payload" | openssl dgst -sha256 -sign test/fixtures/rsa_private_key.pem | base64
    /// ```
    ///
    /// The base64 encoding from this command will be in `STANDARD` form and not URL_SAFE.
    #[test]
    fn sign_and_verify_rs256() {
        let private_key =
            Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();
        // This is standard base64
        let expected_signature =
            "JIHqiBfUknrFPDLT0gxyoufD06S43ZqWN_PzQqHZqQ-met7kZmkSTYB_rUyotLMxlKkuXdnvKmWm\
             dwGAHWEwDvb5392pCmAAtmUIl6LormxJptWYb2PoF5jmtX_lwV8y4RYIh54Ai51162VARQCKAsxL\
             uH772MEChkcpjd31NWzaePWoi_IIk11iqy6uFWmbLLwzD_Vbpl2C6aHR3vQjkXZi05gA3zksjYAh\
             j-m7GgBt0UFOE56A4USjhQwpb4g3NEamgp51_kZ2ULi4Aoo_KJC6ynIm_pR6rEzBgwZjlCUnE-6o\
             5RPQZ8Oau03UDVH2EwZe-Q91LaWRvkKjGg5Tcw";
        let expected_signature_bytes: Vec<u8> = not_err!(base64::decode_config(
            &expected_signature,
            base64::URL_SAFE_NO_PAD
        ));

        let actual_signature =
            not_err!(SignatureAlgorithm::RS256.sign(payload_bytes, &private_key));
        assert_eq!(
            base64::encode_config(&actual_signature, base64::URL_SAFE_NO_PAD),
            expected_signature
        );

        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        not_err!(SignatureAlgorithm::RS256.verify(
            expected_signature_bytes.as_slice(),
            payload_bytes,
            &public_key,
        ));
    }

    #[test]
    fn sign_and_verify_rs256_key_params() {
        use num_bigint::BigUint;
        // There is no way in Ring right now to get these values from the key
        let params = Secret::RSAModulusExponent {
            n: BigUint::parse_bytes(
                b"D57336432EDB91A0A98E3BC2959C08D79017CBDF7AEA6EDCDEC611DA746E1\
                                      DBD144FB4391163E797FB392C438CC70AEA89796D8FCFF69646655AD02E00\
                                      169B5F1C4C9150D3399D80DCE6D8F6F057B105F5FC5EE774B0A8FF20A67D8\
                                      0E6707D380462D2CDCB913E6EE9EA7585CD504AE45B6930BC713D02999E36\
                                      BF449CFFA2385374F3850819056207880A2E8BA47EE8A86CBE4C361D6D54B\
                                      95F2E1668262F79C2774D4234B8D5C6D15A0E95493E308AA98F002A78BB92\
                                      8CB78F1E7E06243AB6D7EAFAB59F6446774B0479F6593F88F763978F14EFB\
                                      7F422B4C66E8EB53FF5E6DC4D3C92952D8413E06E2D9EB1DF50D8224FF3BD\
                                      319FF5E4258D06C578B9527B",
                16,
            )
            .unwrap(),
            e: BigUint::from(65537u32),
        };
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();
        let expected_signature =
            "JIHqiBfUknrFPDLT0gxyoufD06S43ZqWN_PzQqHZqQ-met7kZmkSTYB_rUyotLMxlKkuXdnvKmWm\
             dwGAHWEwDvb5392pCmAAtmUIl6LormxJptWYb2PoF5jmtX_lwV8y4RYIh54Ai51162VARQCKAsxL\
             uH772MEChkcpjd31NWzaePWoi_IIk11iqy6uFWmbLLwzD_Vbpl2C6aHR3vQjkXZi05gA3zksjYAh\
             j-m7GgBt0UFOE56A4USjhQwpb4g3NEamgp51_kZ2ULi4Aoo_KJC6ynIm_pR6rEzBgwZjlCUnE-6o\
             5RPQZ8Oau03UDVH2EwZe-Q91LaWRvkKjGg5Tcw";
        let expected_signature_bytes: Vec<u8> = not_err!(base64::decode_config(
            expected_signature,
            base64::URL_SAFE_NO_PAD
        ));

        not_err!(SignatureAlgorithm::RS256.verify(
            expected_signature_bytes.as_slice(),
            payload_bytes,
            &params,
        ));
    }

    /// This signature is non-deterministic.
    #[test]
    fn sign_and_verify_ps256_round_trip() {
        let private_key =
            Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();

        let actual_signature =
            not_err!(SignatureAlgorithm::PS256.sign(payload_bytes, &private_key));

        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        not_err!(SignatureAlgorithm::PS256.verify(
            actual_signature.as_slice(),
            payload_bytes,
            &public_key,
        ));
    }

    /// This signature is non-deterministic.
    #[test]
    fn sign_and_verify_ps256_round_trip_with_keypair() {
        let key = Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();

        let actual_signature = not_err!(SignatureAlgorithm::PS256.sign(payload_bytes, &key));

        not_err!(SignatureAlgorithm::PS256.verify(
            actual_signature.as_slice(),
            payload_bytes,
            &key,
        ));
    }

    /// To generate a (non-deterministic) signature:
    ///
    /// ```sh
    /// echo -n "payload" | openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
    ///    -sign test/fixtures/rsa_private_key.pem | base64
    /// ```
    ///
    /// The base64 encoding from this command will be in `STANDARD` form and not URL_SAFE.
    #[test]
    fn verify_ps256() {
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();
        let signature =
            "TiMXtt3Wmv/a/tbLWuJPDlFYMfuKsD7U5lbBUn2mBu8DLMLj1EplEZNmkB8w65BgUijnu9hxmhwv\
             ET2k7RrsYamEst6BHZf20hIK1yE/YWaktbVmAZwUDdIpXYaZn8ukTsMT06CDrVk6RXF0EPMaSL33\
             tFNPZpz4/3pYQdxco/n6DpaR5206wsur/8H0FwoyiFKanhqLb1SgZqyc+SXRPepjKc28wzBnfWl4\
             mmlZcJ2xk8O2/t1Y1/m/4G7drBwOItNl7EadbMVCetYnc9EILv39hjcL9JvaA9q0M2RB75DIu8SF\
             9Kr/l+wzUJjWAHthgqSBpe15jLkpO8tvqR89fw==";
        let signature_bytes: Vec<u8> = not_err!(base64::decode(signature.as_bytes()));
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        not_err!(SignatureAlgorithm::PS256.verify(
            signature_bytes.as_slice(),
            payload_bytes,
            &public_key,
        ));
    }

    /// This signature is non-deterministic.
    #[test]
    fn sign_and_verify_es256_round_trip() {
        let private_key = Secret::ecdsa_keypair_from_file(
            SignatureAlgorithm::ES256,
            "test/fixtures/ecdsa_private_key.p8",
        )
        .unwrap();
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();

        let actual_signature =
            not_err!(SignatureAlgorithm::ES256.sign(payload_bytes, &private_key));

        let public_key =
            Secret::public_key_from_file("test/fixtures/ecdsa_public_key.der").unwrap();
        not_err!(SignatureAlgorithm::ES256.verify(
            actual_signature.as_slice(),
            payload_bytes,
            &public_key,
        ));
    }

    /// This signature is non-deterministic.
    #[test]
    fn sign_and_verify_es256_round_trip_with_keypair() {
        let key = Secret::ecdsa_keypair_from_file(
            SignatureAlgorithm::ES256,
            "test/fixtures/ecdsa_private_key.p8",
        )
        .unwrap();
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();

        let actual_signature = not_err!(SignatureAlgorithm::ES256.sign(payload_bytes, &key));

        not_err!(SignatureAlgorithm::ES256.verify(
            actual_signature.as_slice(),
            payload_bytes,
            &key,
        ));
    }

    /// Test case from https://github.com/briansmith/ring/blob/a13b8e2/src/ec/suite_b/ecdsa_verify_fixed_tests.txt
    #[test]
    fn verify_es256() {
        let payload_bytes = Vec::<u8>::new();
        let public_key = "0430345FD47EA21A11129BE651B0884BFAC698377611ACC9F689458E13B9ED7D4B9D7599\
                          A68DCF125E7F31055CCB374CD04F6D6FD2B217438A63F6F667D50EF2F0";
        let public_key = Secret::PublicKey(hex::decode(public_key.as_bytes()).unwrap());
        let signature = "341F6779B75E98BB42E01095DD48356CBF9002DC704AC8BD2A8240B88D3796C6555843B1B\
                         4E264FE6FFE6E2B705A376C05C09404303FFE5D2711F3E3B3A010A1";
        let signature_bytes: Vec<u8> = hex::decode(signature.as_bytes()).unwrap();
        not_err!(SignatureAlgorithm::ES256.verify(
            signature_bytes.as_slice(),
            &payload_bytes,
            &public_key,
        ));
    }

    /// Test case from https://github.com/briansmith/ring/blob/a13b8e2/src/ec/suite_b/ecdsa_verify_fixed_tests.txt
    #[test]
    fn verify_es384() {
        let payload_bytes = Vec::<u8>::new();
        let public_key = "045C5E788A805C77D34128B8401CB59B2373B8B468336C9318252BF39FD31D2507557987\
                          A5180A9435F9FB8EB971C426F1C485170DCB18FB688A257F89387A09FC4C5B8BD4B320616\
                          B54A0A7B1D1D7C6A0C59F6DFF78C78AD4E3D6FCA9C9A17B96";
        let public_key = Secret::PublicKey(hex::decode(public_key.as_bytes()).unwrap());
        let signature = "85AC708D4B0126BAC1F5EEEBDF911409070A286FDDE5649582611B60046DE353761660DD0\
                         3903F58B44148F25142EEF8183475EC1F1392F3D6838ABC0C01724709C446888BED7F2CE4\
                         642C6839DC18044A2A6AB9DDC960BFAC79F6988E62D452";
        let signature_bytes: Vec<u8> = hex::decode(signature.as_bytes()).unwrap();
        not_err!(SignatureAlgorithm::ES384.verify(
            signature_bytes.as_slice(),
            &payload_bytes,
            &public_key,
        ));
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperation")]
    fn verify_es512() {
        let payload: Vec<u8> = vec![];
        let signature: Vec<u8> = vec![];
        let public_key = Secret::PublicKey(vec![]);
        SignatureAlgorithm::ES512
            .verify(signature.as_slice(), payload.as_slice(), &public_key)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_none() {
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        SignatureAlgorithm::None
            .verify(
                signature_bytes,
                "payload".to_string().as_bytes(),
                &Secret::None,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_hs256() {
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        SignatureAlgorithm::HS256
            .verify(
                signature_bytes,
                "payload".to_string().as_bytes(),
                &Secret::Bytes("secret".to_string().into_bytes()),
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_rs256() {
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        SignatureAlgorithm::RS256
            .verify(
                signature_bytes,
                "payload".to_string().as_bytes(),
                &public_key,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_ps256() {
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        SignatureAlgorithm::PS256
            .verify(
                signature_bytes,
                "payload".to_string().as_bytes(),
                &public_key,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_es256() {
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        SignatureAlgorithm::ES256
            .verify(
                signature_bytes,
                "payload".to_string().as_bytes(),
                &public_key,
            )
            .unwrap();
    }

    #[test]
    fn rng_is_created() {
        let rng = SystemRandom::new();
        let mut random: Vec<u8> = vec![0; 8];
        rng.fill(&mut random).unwrap();
    }

    #[test]
    fn aes_gcm_128_encryption_round_trip_fixed_key_nonce() {
        const PAYLOAD: &str = "这个世界值得我们奋战！";
        let key: Vec<u8> = vec![0; 128 / 8];

        let encrypted = not_err!(aes_gcm_encrypt(
            &aead::AES_128_GCM,
            PAYLOAD.as_bytes(),
            &[0; AES_GCM_NONCE_LENGTH],
            &[],
            &key,
        ));
        let decrypted = not_err!(aes_gcm_decrypt(&aead::AES_128_GCM, &encrypted, &key));

        let payload = not_err!(String::from_utf8(decrypted));
        assert_eq!(payload, PAYLOAD);
    }

    #[test]
    fn aes_gcm_128_encryption_round_trip() {
        const PAYLOAD: &str = "这个世界值得我们奋战！";
        let mut key: Vec<u8> = vec![0; 128 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let encrypted = not_err!(aes_gcm_encrypt(
            &aead::AES_128_GCM,
            PAYLOAD.as_bytes(),
            &random_aes_gcm_nonce().unwrap(),
            &[],
            &key,
        ));
        let decrypted = not_err!(aes_gcm_decrypt(&aead::AES_128_GCM, &encrypted, &key));

        let payload = not_err!(String::from_utf8(decrypted));
        assert_eq!(payload, PAYLOAD);
    }

    #[test]
    fn aes_gcm_256_encryption_round_trip() {
        const PAYLOAD: &str = "这个世界值得我们奋战！";
        let mut key: Vec<u8> = vec![0; 256 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let encrypted = not_err!(aes_gcm_encrypt(
            &aead::AES_256_GCM,
            PAYLOAD.as_bytes(),
            &random_aes_gcm_nonce().unwrap(),
            &[],
            &key,
        ));
        let decrypted = not_err!(aes_gcm_decrypt(&aead::AES_256_GCM, &encrypted, &key));

        let payload = not_err!(String::from_utf8(decrypted));
        assert_eq!(payload, PAYLOAD);
    }

    #[test]
    fn aes_gcm_256_encryption_round_trip_fixed_key_nonce() {
        const PAYLOAD: &str = "这个世界值得我们奋战！";
        let key: Vec<u8> = vec![0; 256 / 8];

        let encrypted = not_err!(aes_gcm_encrypt(
            &aead::AES_256_GCM,
            PAYLOAD.as_bytes(),
            &[0; AES_GCM_NONCE_LENGTH],
            &[],
            &key,
        ));
        let decrypted = not_err!(aes_gcm_decrypt(&aead::AES_256_GCM, &encrypted, &key));

        let payload = not_err!(String::from_utf8(decrypted));
        assert_eq!(payload, PAYLOAD);
    }

    /// `KeyManagementAlgorithm::DirectSymmetricKey` returns the same key when CEK is requested
    #[test]
    fn dir_cek_returns_provided_key() {
        let mut key: Vec<u8> = vec![0; 256 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let key = jwk::JWK::<Empty> {
            common: Default::default(),
            additional: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                key_type: Default::default(),
                value: key,
            }),
        };

        let cek_alg = KeyManagementAlgorithm::DirectSymmetricKey;
        let cek = not_err!(cek_alg.cek(jwa::ContentEncryptionAlgorithm::A256GCM, &key));

        assert!(
            verify_slices_are_equal(cek.octet_key().unwrap(), key.octet_key().unwrap()).is_ok()
        );
    }

    /// `KeyManagementAlgorithm::A128GCMKW` returns a random key with the right length when CEK is requested
    #[test]
    fn cek_aes128gcmkw_returns_right_key_length() {
        let mut key: Vec<u8> = vec![0; 128 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let key = jwk::JWK::<Empty> {
            common: Default::default(),
            additional: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                key_type: Default::default(),
                value: key,
            }),
        };

        let cek_alg = KeyManagementAlgorithm::A128GCMKW;
        let cek = not_err!(cek_alg.cek(jwa::ContentEncryptionAlgorithm::A128GCM, &key));
        assert_eq!(cek.octet_key().unwrap().len(), 128 / 8);
        assert!(
            verify_slices_are_equal(cek.octet_key().unwrap(), key.octet_key().unwrap()).is_err()
        );

        let cek = not_err!(cek_alg.cek(jwa::ContentEncryptionAlgorithm::A256GCM, &key));
        assert_eq!(cek.octet_key().unwrap().len(), 256 / 8);
        assert!(
            verify_slices_are_equal(cek.octet_key().unwrap(), key.octet_key().unwrap()).is_err()
        );
    }

    /// `KeyManagementAlgorithm::A256GCMKW` returns a random key with the right length when CEK is requested
    #[test]
    fn cek_aes256gcmkw_returns_right_key_length() {
        let mut key: Vec<u8> = vec![0; 256 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let key = jwk::JWK::<Empty> {
            common: Default::default(),
            additional: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                key_type: Default::default(),
                value: key,
            }),
        };

        let cek_alg = KeyManagementAlgorithm::A256GCMKW;
        let cek = not_err!(cek_alg.cek(jwa::ContentEncryptionAlgorithm::A128GCM, &key));
        assert_eq!(cek.octet_key().unwrap().len(), 128 / 8);
        assert!(
            verify_slices_are_equal(cek.octet_key().unwrap(), key.octet_key().unwrap()).is_err()
        );

        let cek = not_err!(cek_alg.cek(jwa::ContentEncryptionAlgorithm::A256GCM, &key));
        assert_eq!(cek.octet_key().unwrap().len(), 256 / 8);
        assert!(
            verify_slices_are_equal(cek.octet_key().unwrap(), key.octet_key().unwrap()).is_err()
        );
    }

    #[test]
    fn aes128gcmkw_key_encryption_round_trip() {
        let mut key: Vec<u8> = vec![0; 128 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let key = jwk::JWK::<Empty> {
            common: Default::default(),
            additional: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                key_type: Default::default(),
                value: key,
            }),
        };

        let nonce = random_aes_gcm_nonce().unwrap();

        let cek_alg = KeyManagementAlgorithm::A128GCMKW;
        let enc_alg = jwa::ContentEncryptionAlgorithm::A128GCM; // determines the CEK
        let cek = not_err!(cek_alg.cek(enc_alg, &key));

        let mut header = CekAlgorithmHeader {
            nonce: Some(nonce),
            ..Default::default()
        };
        let encrypted_cek = not_err!(cek_alg.wrap_key(cek.octet_key().unwrap(), &key, &mut header));
        let decrypted_cek = not_err!(cek_alg.unwrap_key(&encrypted_cek, &mut header, &key));

        assert!(verify_slices_are_equal(
            cek.octet_key().unwrap(),
            decrypted_cek.octet_key().unwrap(),
        )
        .is_ok());
    }

    #[test]
    fn aes256gcmkw_key_encryption_round_trip() {
        let mut key: Vec<u8> = vec![0; 256 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let key = jwk::JWK::<Empty> {
            common: Default::default(),
            additional: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                key_type: Default::default(),
                value: key,
            }),
        };

        let nonce = random_aes_gcm_nonce().unwrap();

        let cek_alg = KeyManagementAlgorithm::A256GCMKW;
        let enc_alg = jwa::ContentEncryptionAlgorithm::A128GCM; // determines the CEK
        let cek = not_err!(cek_alg.cek(enc_alg, &key));

        let mut header = CekAlgorithmHeader {
            nonce: Some(nonce),
            ..Default::default()
        };
        let encrypted_cek = not_err!(cek_alg.wrap_key(cek.octet_key().unwrap(), &key, &mut header));
        let decrypted_cek = not_err!(cek_alg.unwrap_key(&encrypted_cek, &mut header, &key));

        assert!(verify_slices_are_equal(
            cek.octet_key().unwrap(),
            decrypted_cek.octet_key().unwrap(),
        )
        .is_ok());
    }

    /// `ContentEncryptionAlgorithm::A128GCM` generates CEK of the right length
    #[test]
    fn aes128gcm_key_length() {
        let enc_alg = jwa::ContentEncryptionAlgorithm::A128GCM;
        let cek = not_err!(enc_alg.generate_key());
        assert_eq!(cek.len(), 128 / 8);
    }

    /// `ContentEncryptionAlgorithm::A256GCM` generates CEK of the right length
    #[test]
    fn aes256gcm_key_length() {
        let enc_alg = jwa::ContentEncryptionAlgorithm::A256GCM;
        let cek = not_err!(enc_alg.generate_key());
        assert_eq!(cek.len(), 256 / 8);
    }

    #[test]
    fn aes128gcm_encryption_round_trip() {
        let mut key: Vec<u8> = vec![0; 128 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let key = jwk::JWK::<Empty> {
            common: Default::default(),
            additional: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                key_type: Default::default(),
                value: key,
            }),
        };

        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };

        let payload = "狼よ、我が敵を食らえ！";
        let aad = "My servants never die!";
        let enc_alg = jwa::ContentEncryptionAlgorithm::A128GCM;
        let encrypted_payload =
            not_err!(enc_alg.encrypt(payload.as_bytes(), aad.as_bytes(), &key, &options,));

        let decrypted_payload = not_err!(enc_alg.decrypt(&encrypted_payload, &key));
        assert!(verify_slices_are_equal(payload.as_bytes(), &decrypted_payload).is_ok());
    }

    #[test]
    fn aes1256gcm_encryption_round_trip() {
        let mut key: Vec<u8> = vec![0; 256 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let key = jwk::JWK::<Empty> {
            common: Default::default(),
            additional: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                key_type: Default::default(),
                value: key,
            }),
        };

        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };

        let payload = "狼よ、我が敵を食らえ！";
        let aad = "My servants never die!";
        let enc_alg = jwa::ContentEncryptionAlgorithm::A256GCM;
        let encrypted_payload =
            not_err!(enc_alg.encrypt(payload.as_bytes(), aad.as_bytes(), &key, &options,));

        let decrypted_payload = not_err!(enc_alg.decrypt(&encrypted_payload, &key));
        assert!(verify_slices_are_equal(payload.as_bytes(), &decrypted_payload).is_ok());
    }

    #[test]
    fn aescbc_hmacsha() {
        struct Test {
            alg: AES_CBC_HMAC_SHA,
            key: &'static [u8],
            enc: [u8; 144],
            tag: &'static [u8],
        }

        use hex_literal::hex;
        // from https://datatracker.ietf.org/doc/html/rfc7518#appendix-B
        let tests = [
            Test {
                alg: AES_CBC_HMAC_SHA::A128CBC_HS256,
                key: &hex!(
                    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
                    "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"
                ),
                enc: hex!(
                    "c8 0e df a3 2d df 39 d5 ef 00 c0 b4 68 83 42 79"
                    "a2 e4 6a 1b 80 49 f7 92 f7 6b fe 54 b9 03 a9 c9"
                    "a9 4a c9 b4 7a d2 65 5c 5f 10 f9 ae f7 14 27 e2"
                    "fc 6f 9b 3f 39 9a 22 14 89 f1 63 62 c7 03 23 36"
                    "09 d4 5a c6 98 64 e3 32 1c f8 29 35 ac 40 96 c8"
                    "6e 13 33 14 c5 40 19 e8 ca 79 80 df a4 b9 cf 1b"
                    "38 4c 48 6f 3a 54 c5 10 78 15 8e e5 d7 9d e5 9f"
                    "bd 34 d8 48 b3 d6 95 50 a6 76 46 34 44 27 ad e5"
                    "4b 88 51 ff b5 98 f7 f8 00 74 b9 47 3c 82 e2 db"
                ),
                tag: &hex!("65 2c 3f a3 6b 0a 7c 5b 32 19 fa b3 a3 0b c1 c4"),
            },
            Test {
                alg: AES_CBC_HMAC_SHA::A192CBC_HS384,
                key: &hex!(
                    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
                    "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"
                    "20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f"
                ),
                enc: hex!(
                    "ea 65 da 6b 59 e6 1e db 41 9b e6 2d 19 71 2a e5"
                    "d3 03 ee b5 00 52 d0 df d6 69 7f 77 22 4c 8e db"
                    "00 0d 27 9b dc 14 c1 07 26 54 bd 30 94 42 30 c6"
                    "57 be d4 ca 0c 9f 4a 84 66 f2 2b 22 6d 17 46 21"
                    "4b f8 cf c2 40 0a dd 9f 51 26 e4 79 66 3f c9 0b"
                    "3b ed 78 7a 2f 0f fc bf 39 04 be 2a 64 1d 5c 21"
                    "05 bf e5 91 ba e2 3b 1d 74 49 e5 32 ee f6 0a 9a"
                    "c8 bb 6c 6b 01 d3 5d 49 78 7b cd 57 ef 48 49 27"
                    "f2 80 ad c9 1a c0 c4 e7 9c 7b 11 ef c6 00 54 e3"
                ),
                tag: &hex!(
                    "84 90 ac 0e 58 94 9b fe 51 87 5d 73 3f 93 ac 20"
                    "75 16 80 39 cc c7 33 d7"
                ),
            },
            Test {
                alg: AES_CBC_HMAC_SHA::A256CBC_HS512,
                key: &hex!(
                    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
                    "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"
                    "20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f"
                    "30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f"
                ),
                enc: hex!(
                    "4a ff aa ad b7 8c 31 c5 da 4b 1b 59 0d 10 ff bd"
                    "3d d8 d5 d3 02 42 35 26 91 2d a0 37 ec bc c7 bd"
                    "82 2c 30 1d d6 7c 37 3b cc b5 84 ad 3e 92 79 c2"
                    "e6 d1 2a 13 74 b7 7f 07 75 53 df 82 94 10 44 6b"
                    "36 eb d9 70 66 29 6a e6 42 7e a7 5c 2e 08 46 a1"
                    "1a 09 cc f5 37 0d c8 0b fe cb ad 28 c7 3f 09 b3"
                    "a3 b7 5e 66 2a 25 94 41 0a e4 96 b2 e2 e6 60 9e"
                    "31 e6 e0 2c c8 37 f0 53 d2 1f 37 ff 4f 51 95 0b"
                    "be 26 38 d0 9d d7 a4 93 09 30 80 6d 07 03 b1 f6"
                ),
                tag: &hex!(
                    "4d d3 b4 c0 88 a7 f4 5c 21 68 39 64 5b 20 12 bf"
                    "2e 62 69 a8 c5 6a 81 6d bc 1b 26 77 61 95 5b c5"
                ),
            },
        ];

        let payload = hex!(
            "41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20"
            "6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75"
            "69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65"
            "74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62"
            "65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69"
            "6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66"
            "20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f"
            "75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65"
        );
        let iv = hex!("1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04");
        let aad = hex!(
            "54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63"
            "69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20"
            "4b 65 72 63 6b 68 6f 66 66 73"
        );

        for test in tests {
            let res = aes_cbc_sha2_encrypt(test.alg, &payload, &iv, &aad, test.key).unwrap();

            assert_eq!(res.encrypted, test.enc);
            assert_eq!(res.tag, test.tag);

            let res = aes_cbc_sha2_decrypt(test.alg, &res, test.key).unwrap();

            assert_eq!(res, payload);
        }
    }

    #[test]
    fn aes128_keywrapping_128() {
        let kek = hex_literal::hex!("000102030405060708090A0B0C0D0E0F");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF");

        let mut out = [0; 8 + 16];
        out[8..].copy_from_slice(&data);
        block_cipher_key_wrap::<aes::Aes128Enc>(&kek, &mut out).unwrap();

        assert_eq!(
            out,
            hex_literal::hex!("1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5")
        );

        block_cipher_key_unwrap::<aes::Aes128Dec>(&kek, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    fn aes192_keywrapping_128() {
        let kek = hex_literal::hex!("000102030405060708090A0B0C0D0E0F1011121314151617");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF");

        let mut out = [0; 8 + 16];
        out[8..].copy_from_slice(&data);
        block_cipher_key_wrap::<aes::Aes192Enc>(&kek, &mut out).unwrap();

        assert_eq!(
            out,
            hex_literal::hex!("96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D")
        );

        block_cipher_key_unwrap::<aes::Aes192Dec>(&kek, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    fn aes256_keywrapping_128() {
        let kek =
            hex_literal::hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF");

        let mut out = [0; 8 + 16];
        out[8..].copy_from_slice(&data);
        block_cipher_key_wrap::<aes::Aes256Enc>(&kek, &mut out).unwrap();

        assert_eq!(
            out,
            hex_literal::hex!("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7")
        );

        block_cipher_key_unwrap::<aes::Aes256Dec>(&kek, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    fn aes192_keywrapping_192() {
        let kek = hex_literal::hex!("000102030405060708090A0B0C0D0E0F1011121314151617");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF0001020304050607");

        let mut out = [0; 8 + 24];
        out[8..].copy_from_slice(&data);
        block_cipher_key_wrap::<aes::Aes192Enc>(&kek, &mut out).unwrap();

        assert_eq!(
            out,
            hex_literal::hex!(
                "031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2"
            )
        );

        block_cipher_key_unwrap::<aes::Aes192Dec>(&kek, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    fn aes256_keywrapping_192() {
        let kek =
            hex_literal::hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF0001020304050607");

        let mut out = [0; 8 + 24];
        out[8..].copy_from_slice(&data);
        block_cipher_key_wrap::<aes::Aes256Enc>(&kek, &mut out).unwrap();

        assert_eq!(
            out,
            hex_literal::hex!(
                "A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1"
            )
        );

        block_cipher_key_unwrap::<aes::Aes256Dec>(&kek, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    fn aes256_keywrapping_256() {
        let kek =
            hex_literal::hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let data =
            hex_literal::hex!("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");

        let mut out = [0; 8 + 32];
        out[8..].copy_from_slice(&data);
        block_cipher_key_wrap::<aes::Aes256Enc>(&kek, &mut out).unwrap();

        assert_eq!(
            out,
            hex_literal::hex!(
                "28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326
            CBC7F0E71A99F43B FB988B9B7A02DD21"
            )
        );

        block_cipher_key_unwrap::<aes::Aes256Dec>(&kek, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }
}
