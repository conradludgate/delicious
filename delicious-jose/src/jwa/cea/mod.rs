//! [Cryptographic Algorithms for Content Encryption](https://datatracker.ietf.org/doc/html/rfc7518#section-5)
use crate::errors::Error;

pub(crate) mod aes_cbc_hmac_sha;
pub(crate) mod aes_gcm;
pub use self::aes_gcm::{AesGcm, A128GCM, A256GCM};
pub use aes_cbc_hmac_sha::{AesCbcHmacSha2, A128CBC_HS256, A192CBC_HS384, A256CBC_HS512};
use serde::{Deserialize, Serialize};

/// [Cryptographic Algorithms for Content Encryption](https://datatracker.ietf.org/doc/html/rfc7518#section-5)
pub trait CEA {
    /// The name specified in the `enc` header.
    const ENC: Algorithm;
    /// Content Encryption Key
    type Cek;
    /// Initialization Vector length in bytes
    const IV: usize;

    /// Generate a random content encryption key
    fn generate_cek() -> Self::Cek;

    /// Encrypts the payload
    fn encrypt(
        cek: &Self::Cek,
        payload: &[u8],
        iv: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<EncryptionResult, Error>;

    /// Decrypts the payload
    fn decrypt(cek: &Self::Cek, res: &EncryptionResult) -> Result<Vec<u8>, Error>;
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

/// Algorithms meant for content encryption.
/// See [RFC7518#5](https://tools.ietf.org/html/rfc7518#section-5)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum Algorithm {
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

impl Algorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A128CBC_HS256 => "A128CBC-HS256",
            Self::A192CBC_HS384 => "A192CBC-HS384",
            Self::A256CBC_HS512 => "A256CBC-HS512",
            Self::A128GCM => "A128GCM",
            Self::A192GCM => "A192GCM",
            Self::A256GCM => "A256GCM",
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::A128GCM
    }
}
