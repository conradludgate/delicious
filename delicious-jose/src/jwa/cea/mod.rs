//! [Cryptographic Algorithms for Content Encryption](https://datatracker.ietf.org/doc/html/rfc7518#section-5)
use crate::errors::Error;

use super::EncryptionResult;

pub(crate) mod aes_cbc_hmac_sha;
pub(crate) mod aes_gcm;
pub use self::aes_gcm::{AesGcm, A128GCM, A256GCM};
pub use aes_cbc_hmac_sha::{AesCbcHmacSha2, A128CBC_HS256, A192CBC_HS384, A256CBC_HS512};

/// [Cryptographic Algorithms for Content Encryption](https://datatracker.ietf.org/doc/html/rfc7518#section-5)
pub trait CEA {
    /// The name specified in the `enc` header.
    const ENC: &'static str;
    /// Content Encryption Key
    type Cek;

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
