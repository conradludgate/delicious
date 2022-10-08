use super::KMA;
use crate::jwa::cea::AesGcm;
use crate::{errors::Error, jwk::OctetKey};
use serde::{Deserialize, Serialize};

/// Key wrapping with AES GCM. [RFC7518#4.7](https://tools.ietf.org/html/rfc7518#section-4.7)
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum AesGcmKwAlgorithm {
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
/// See:
/// * [`A128GCMKW`](crate::jwa::kma::A128GCMKW) - Key wrapping with AES GCM using 128-bit key
/// * [`A192GCMKW`](crate::jwa::kma::A192GCMKW) - Key wrapping with AES GCM using 192-bit key
/// * [`A256GCMKW`](crate::jwa::kma::A256GCMKW) - Key wrapping with AES GCM using 256-bit key
pub type AesGcmKw<Aes> = AesGcm<Aes>;

/// Key wrapping with AES GCM using 128-bit key
pub type A128GCMKW = AesGcmKw<aes::Aes128>;

/// Key wrapping with AES GCM using 192-bit key
pub type A192GCMKW = AesGcmKw<aes::Aes192>;

/// Key wrapping with AES GCM using 256-bit key
pub type A256GCMKW = AesGcmKw<aes::Aes256>;

/// Header for AES GCM Keywrap algorithm.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AesGcmKwHeader {
    /// The initialization vector, or nonce used in the encryption
    pub iv: [u8; 12],
    /// The authentication tag resulting from the encryption
    pub tag: [u8; 16],
}

macro_rules! aes_gcm {
    ($id:ident, $aes:ty, $name:ident) => {
        impl KMA for $id {
            const ALG: super::Algorithm = super::Algorithm::AesGcmKw(AesGcmKwAlgorithm::$name);
            type Key = OctetKey;
            type Header = AesGcmKwHeader;
            type WrapSettings = [u8; 12];

            fn wrap(
                cek: &[u8],
                key: &Self::Key,
                iv: Self::WrapSettings,
            ) -> Result<(Vec<u8>, Self::Header), Error> {
                let res = Self::encrypt_inner(&key.value, &cek, &iv, &[])?;
                let header = AesGcmKwHeader {
                    iv,
                    tag: res[3]
                        .try_into()
                        .expect("aes-gcm tag should always be 16 bytes"),
                };
                Ok((res.take_payload(), header))
            }

            fn unwrap<'c>(
                encrypted_cek: &'c mut [u8],
                key: &'c Self::Key,
                header: Self::Header,
            ) -> Result<&'c [u8], Error> {
                Self::decrypt_inner(&key.value, encrypted_cek, &header.iv, &header.tag, &[])
            }
        }
    };
}

aes_gcm!(A128GCMKW, aes::Aes128, A128);
aes_gcm!(A192GCMKW, aes::Aes192, A192);
aes_gcm!(A256GCMKW, aes::Aes256, A256);

impl From<AesGcmKwAlgorithm> for super::Algorithm {
    fn from(a: AesGcmKwAlgorithm) -> Self {
        super::Algorithm::AesGcmKw(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::{random_array, random_vec};

    pub fn random_aes_gcm_nonce() -> [u8; 12] {
        random_array()
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
        K: KMA<WrapSettings = [u8; 12]>,
    {
        let cek = random_vec(128 / 8);
        let nonce = random_aes_gcm_nonce();

        let (mut encrypted_cek, settings) = K::wrap(&cek, key, nonce).unwrap();
        assert_ne!(cek, encrypted_cek);

        let decrypted_cek = K::unwrap(&mut encrypted_cek, key, settings).unwrap();
        assert_eq!(cek, decrypted_cek);
    }
}
