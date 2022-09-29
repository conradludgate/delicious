//! [Cryptographic Algorithms for Content Encryption](https://datatracker.ietf.org/doc/html/rfc7518#section-5)
use crate::errors::Error;

use super::EncryptionResult;

pub(crate) mod aes_cbc_hmac_sha;

/// Content Encryption Algorithms
pub trait CEA {
    /// enc header value
    const ENC: &'static str;
    /// Content Encryption Key
    type Cek;

    fn encrypt(
        cek: Self::Cek,
        payload: &[u8],
        iv: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<EncryptionResult, Error>;

    fn decrypt(cek: Self::Cek, res: &EncryptionResult) -> Result<Vec<u8>, Error>;
}
