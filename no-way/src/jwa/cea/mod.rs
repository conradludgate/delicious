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
    /// Creates the `EncryptionResult` with the 3 known values, and spare space for the tag.
    ///
    /// Safety: `payload_size` must be >= `payload.len()`
    pub(crate) unsafe fn new_without_tag(
        mut aad: Vec<u8>,
        iv: &[u8],
        payload: &[u8],
        payload_size: usize,
        tag_size: usize,
    ) -> Self {
        debug_assert!(payload_size >= payload.len());

        let nonce_index = aad.len();
        let payload_index = nonce_index + iv.len();
        let tag = payload_index + payload_size;
        aad.reserve(payload_size + iv.len() + tag_size);

        // safety, writes into pre-alloc memory
        {
            let bytes = aad.spare_capacity_mut();
            let mut p = bytes.as_mut_ptr().cast::<u8>();

            p.copy_from_nonoverlapping(iv.as_ptr(), iv.len());
            p = p.add(iv.len());
            p.copy_from_nonoverlapping(payload.as_ptr(), payload.len());
            p = p.add(payload.len());
            p.write_bytes(0, payload_size - payload.len());

            aad.set_len(tag);
        }

        Self {
            nonce: nonce_index,
            payload: payload_index,
            tag,
            data: aad,
        }
    }
    /// Adds the tag to the end of the buffer (without allocating)
    ///
    /// Safety: must have `tag_size` spare bytes available
    /// (guaranteed if specifed in the [`new_without_tag`] call)
    pub(crate) unsafe fn push_tag(&mut self, tag: &[u8]) {
        debug_assert_eq!(self.tag, self.data.len(), "You pushed the tag already");
        let bytes = self.data.spare_capacity_mut();
        debug_assert!(bytes.len() >= tag.len());

        let p = bytes.as_mut_ptr().cast::<u8>();
        p.copy_from_nonoverlapping(tag.as_ptr(), tag.len());

        self.data.set_len(self.tag + tag.len());
    }

    pub fn aad(&self) -> &[u8] {
        unsafe { self.data.get_unchecked(..self.nonce) }
    }
    pub fn nonce(&self) -> &[u8] {
        unsafe { self.data.get_unchecked(self.nonce..self.payload) }
    }
    pub fn encrypted_payload(&self) -> &[u8] {
        unsafe { self.data.get_unchecked(self.payload..self.tag) }
    }
    pub fn tag(&self) -> &[u8] {
        unsafe { self.data.get_unchecked(self.tag..) }
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
