//! [Cryptographic Algorithms for Content Encryption](https://datatracker.ietf.org/doc/html/rfc7518#section-5)
use crate::errors::Error;

pub(crate) mod aes_cbc_hmac_sha;
pub(crate) mod aes_gcm;
pub use self::aes_gcm::{AesGcm, A128GCM, A192GCM, A256GCM};
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
        iv: &[u8],
        aad: Vec<u8>,
    ) -> Result<EncryptionResult, Error>;

    /// Decrypts the payload
    fn decrypt(cek: &Self::Cek, res: &EncryptionResult) -> Result<Vec<u8>, Error>;
}

/// The result returned from an encryption operation
/// 
/// This is a more internal focused type. 
/// It's compressed as [AAD,NONCE,PAYLOAD,TAG] all in 1 vec to avoid having
/// multiple allocations.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct EncryptionResult {
    pub(crate) data: Vec<u8>,
    pub(crate) nonce: usize,
    pub(crate) payload: usize,
    pub(crate) tag: usize,
}

impl EncryptionResult {
    pub(crate) fn new_with_aad(aad: Vec<u8>) -> Self {
        Self {
            nonce: aad.len(),
            payload: aad.len(),
            tag: aad.len(),
            data: aad,
        }
    }
    pub(crate) fn push_nonce(&mut self, nonce: &[u8]) {
        debug_assert_eq!(self.nonce, self.data.len(), "You pushed the payload or tag before the nonce");
        self.data.extend_from_slice(nonce);
        self.payload = self.data.len();
        self.tag = self.data.len();
    }
    pub(crate) fn push_payload_with_padded_len(&mut self, payload: &[u8], padded_len: usize) {
        debug_assert_eq!(self.payload, self.data.len(), "You pushed the tag before the payload");
        self.data.extend_from_slice(payload);
        self.data.resize(self.payload+padded_len, 0);
        self.tag = self.data.len();
    }
    pub(crate) fn push_tag(&mut self, tag: &[u8]) {
        debug_assert_eq!(self.tag, self.data.len(), "You pushed the tag already");
        self.data.extend_from_slice(tag);
    }

    pub fn aad(&self) -> &[u8] {
        &self.data[..self.nonce]
    }
    pub fn nonce(&self) -> &[u8] {
        &self.data[self.nonce..self.payload]
    }
    pub fn encrypted_payload(&self) -> &[u8] {
        &self.data[self.payload..self.tag]
    }
    pub fn tag(&self) -> &[u8] {
        &self.data[self.tag..]
    }
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
    A192GCM,
    /// AES GCM using 256-bit key
    A256GCM,
}

impl Algorithm {
    /// Turn this content-encryption algorithm into it's
    /// well-known `enc` header name
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
