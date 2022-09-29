use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::{errors::Error, jwa::OctetKey};

use super::KMA;

/// Key wrapping with AES GCM. [RFC7518#4.7](https://tools.ietf.org/html/rfc7518#section-4.7)
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum AES_GCM {
    /// Key wrapping with AES GCM using 128-bit key alg
    A128,
    /// Key wrapping with AES GCM using 192-bit key alg.
    /// This is [not supported](https://github.com/briansmith/ring/issues/112) by `ring`.
    A192,
    /// Key wrapping with AES GCM using 256-bit key alg
    A256,
}

/// [Key Encryption with AES GCM](https://datatracker.ietf.org/doc/html/rfc7518#section-4.7)
///
/// See
/// * [`A128GCMKW`] - Key wrapping with AES GCM using 128-bit key
/// * [`A256GCMKW`] - Key wrapping with AES GCM using 256-bit key
#[derive(Clone, Copy)]
pub struct AesGcmKw<AES>(PhantomData<AES>);

impl<Aes> PartialEq for AesGcmKw<Aes> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}
impl<Aes> Eq for AesGcmKw<Aes> {}

impl<Aes> std::fmt::Debug for AesGcmKw<Aes>
where
    Self: KMA,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(Self::ALG.as_str())
    }
}

#[allow(non_camel_case_types)]
/// Key wrapping with AES GCM using 128-bit key
pub type A128GCMKW = AesGcmKw<aes_gcm::Aes128Gcm>;
#[allow(non_camel_case_types)]
/// Key wrapping with AES GCM using 256-bit key
pub type A256GCMKW = AesGcmKw<aes_gcm::Aes256Gcm>;

/// Header for AES GCM Keywrap algorithm.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AesGcmKwHeader {
    /// The initialization vector, or nonce used in the encryption
    #[serde(rename = "iv")]
    pub nonce: Vec<u8>,
    /// The authentication tag resulting from the encryption
    pub tag: Vec<u8>,
}

use crate::jwa::cea::AesGcm;

macro_rules! aes_gcm {
    ($id:ident, $aes:ty, $name:ident) => {
        impl KMA for $id {
            const ALG: super::Algorithm = super::Algorithm::AES_GCM_KW(AES_GCM::$name);
            type Key = OctetKey;
            type Cek = OctetKey;
            type Header = AesGcmKwHeader;
            type WrapSettings = Vec<u8>;

            fn wrap(
                cek: &Self::Cek,
                key: &Self::Key,
                settings: Self::WrapSettings,
            ) -> Result<(Vec<u8>, Self::Header), Error> {
                let res = AesGcm::<$aes>::encrypt_inner(&key.0, &cek.0, settings, Vec::new())?;
                let header = AesGcmKwHeader {
                    nonce: res.nonce,
                    tag: res.tag,
                };
                Ok((res.encrypted, header))
            }

            fn unwrap(
                encrypted_cek: &[u8],
                key: &Self::Key,
                header: Self::Header,
            ) -> Result<Self::Cek, Error> {
                let res = AesGcm::<$aes>::decrypt_inner(
                    &key.0,
                    encrypted_cek,
                    &header.nonce,
                    &header.tag,
                    &[],
                )?;
                Ok(OctetKey(res))
            }
        }
    };
}

aes_gcm!(A128GCMKW, aes_gcm::Aes128Gcm, A128);
aes_gcm!(A256GCMKW, aes_gcm::Aes256Gcm, A256);

impl From<AES_GCM> for super::Algorithm {
    fn from(a: AES_GCM) -> Self {
        super::Algorithm::AES_GCM_KW(a)
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    pub fn random_vec(len: usize) -> Vec<u8> {
        let mut nonce = vec![0; len];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    pub fn random_aes_gcm_nonce() -> Vec<u8> {
        random_vec(12)
    }

    use super::*;

    #[test]
    fn aes128gcmkw_key_encryption_round_trip() {
        let key = OctetKey(random_vec(128 / 8));
        let cek = OctetKey(random_vec(128 / 8));
        let nonce = random_aes_gcm_nonce();

        let (encrypted_cek, settings) = A128GCMKW::wrap(&cek, &key, nonce).unwrap();
        let decrypted_cek = A128GCMKW::unwrap(&encrypted_cek, &key, settings).unwrap();

        assert_eq!(cek, decrypted_cek);
    }

    #[test]
    fn aes256gcmkw_key_encryption_round_trip() {
        let key = OctetKey(random_vec(256 / 8));
        let cek = OctetKey(random_vec(128 / 8));
        let nonce = random_aes_gcm_nonce();

        let (encrypted_cek, settings) = A256GCMKW::wrap(&cek, &key, nonce).unwrap();
        let decrypted_cek = A256GCMKW::unwrap(&encrypted_cek, &key, settings).unwrap();

        assert_eq!(cek, decrypted_cek);
    }
}
