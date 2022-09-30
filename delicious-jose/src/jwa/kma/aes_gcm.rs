use super::KMA;
pub use crate::jwa::cea::AesGcm;
use crate::{errors::Error, jwk::OctetKey};
use serde::{Deserialize, Serialize};

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

#[allow(non_camel_case_types)]
/// Key wrapping with AES GCM using 128-bit key
pub type A128GCMKW = AesGcm<aes::Aes128>;
#[allow(non_camel_case_types)]
/// Key wrapping with AES GCM using 192-bit key
pub type A192GCMKW = AesGcm<aes::Aes192>;
#[allow(non_camel_case_types)]
/// Key wrapping with AES GCM using 256-bit key
pub type A256GCMKW = AesGcm<aes::Aes256>;

/// Header for AES GCM Keywrap algorithm.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AesGcmKwHeader {
    /// The initialization vector, or nonce used in the encryption
    #[serde(rename = "iv")]
    pub nonce: Vec<u8>,
    /// The authentication tag resulting from the encryption
    pub tag: Vec<u8>,
}

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
                let res = Self::encrypt_inner(&key.value, &cek.value, settings, Vec::new())?;
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
                let res = Self::decrypt_inner(
                    &key.value,
                    encrypted_cek,
                    &header.nonce,
                    &header.tag,
                    &[],
                )?;
                Ok(OctetKey::new(res))
            }
        }
    };
}

aes_gcm!(A128GCMKW, aes::Aes128, A128);
aes_gcm!(A192GCMKW, aes::Aes192, A192);
aes_gcm!(A256GCMKW, aes::Aes256, A256);

impl From<AES_GCM> for super::Algorithm {
    fn from(a: AES_GCM) -> Self {
        super::Algorithm::AES_GCM_KW(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::random_vec;

    pub fn random_aes_gcm_nonce() -> Vec<u8> {
        random_vec(12)
    }

    #[test]
    fn aes128gcmkw_key_encryption_round_trip() {
        let key = OctetKey::new(random_vec(128 / 8));
        kma_round_trip::<A128GCMKW>(&key);
    }

    #[test]
    fn aes192gcmkw_key_encryption_round_trip() {
        let key = OctetKey::new(random_vec(192 / 8));
        kma_round_trip::<A192GCMKW>(&key);
    }

    #[test]
    fn aes256gcmkw_key_encryption_round_trip() {
        let key = OctetKey::new(random_vec(256 / 8));
        kma_round_trip::<A256GCMKW>(&key);
    }

    fn kma_round_trip<K>(key: &K::Key)
    where
        K: KMA<Cek = OctetKey, WrapSettings = Vec<u8>>,
    {
        let cek = OctetKey::new(random_vec(128 / 8));
        let nonce = random_aes_gcm_nonce();

        let (encrypted_cek, settings) = K::wrap(&cek, key, nonce).unwrap();
        let decrypted_cek = K::unwrap(&encrypted_cek, key, settings).unwrap();

        assert_ne!(cek.as_bytes(), encrypted_cek);
        assert_eq!(cek, decrypted_cek);
    }
}
