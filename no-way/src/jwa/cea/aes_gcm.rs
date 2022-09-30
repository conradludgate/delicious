use std::marker::PhantomData;

use aead::{
    generic_array::{ArrayLength, GenericArray},
    AeadInPlace, KeyInit,
};

use super::{EncryptionResult, CEA};
use crate::{jwk::OctetKey, Error};

/// [Content Encryption with AES GCM](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
///
/// See:
/// * [`A128GCM`] - AES GCM using 128-bit key
/// * [`A192GCM`] - AES GCM using 192-bit key
/// * [`A256GCM`] - AES GCM using 256-bit key
pub struct AesGcm<Aes>(PhantomData<Aes>);

impl<Aes> Clone for AesGcm<Aes> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<Aes> Copy for AesGcm<Aes> {}

impl<Aes> PartialEq for AesGcm<Aes> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}
impl<Aes> Eq for AesGcm<Aes> {}

impl<Aes> std::fmt::Debug for AesGcm<Aes>
where
    Self: CEA,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(Self::ENC.as_str())
    }
}

#[allow(non_camel_case_types)]
/// [Content Encryption with AES GCM using 128-bit key](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
pub type A128GCM = AesGcm<aes::Aes128>;
#[allow(non_camel_case_types)]
/// [Content Encryption with AES GCM using 192-bit key](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
pub type A192GCM = AesGcm<aes::Aes192>;
#[allow(non_camel_case_types)]
/// [Content Encryption with AES GCM using 256-bit key](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
pub type A256GCM = AesGcm<aes::Aes256>;

macro_rules! aes_gcm {
    ($id:ident, $aes:ty, $key_len:expr) => {
        impl $id {
            pub(crate) fn encrypt_inner(
                cek: &[u8],
                payload: &[u8],
                iv: Vec<u8>,
                aad: Vec<u8>,
            ) -> Result<EncryptionResult, Error> {
                let cipher =
                    ::aes_gcm::AesGcm::<$aes, aes::cipher::consts::U12>::new_from_slice(&cek)?;
                let nonce: &::aes_gcm::Nonce<_> = from_slice(&iv)?;
                let mut payload = payload.to_vec();
                let tag = cipher
                    .encrypt_in_place_detached(nonce, &aad, &mut payload)
                    .map_err(|_| Error::UnspecifiedCryptographicError)?
                    .to_vec();
                Ok(EncryptionResult {
                    nonce: iv,
                    encrypted: payload,
                    tag,
                    additional_data: aad,
                })
            }

            pub(crate) fn decrypt_inner(
                cek: &[u8],
                encrypted: &[u8],
                nonce: &[u8],
                tag: &[u8],
                aad: &[u8],
            ) -> Result<Vec<u8>, Error> {
                let cipher =
                    ::aes_gcm::AesGcm::<$aes, aes::cipher::consts::U12>::new_from_slice(&cek)?;
                let nonce: &::aes_gcm::Nonce<_> = from_slice(&nonce)?;
                let tag: &::aes_gcm::Tag = from_slice(&tag)?;
                let mut in_out: Vec<u8> = encrypted.to_vec();
                cipher
                    .decrypt_in_place_detached(nonce, &aad, &mut in_out, tag)
                    .map_err(|_| Error::UnspecifiedCryptographicError)?;
                Ok(in_out)
            }
        }

        impl CEA for $id {
            const ENC: super::Algorithm = super::Algorithm::$id;
            type Cek = OctetKey;
            const IV: usize = 96 / 8;

            fn generate_cek() -> Self::Cek {
                let mut rng = rand::thread_rng();
                let mut key = vec![0; $key_len];
                rand::Rng::fill(&mut rng, key.as_mut_slice());
                OctetKey::new(key)
            }

            fn encrypt(
                cek: &Self::Cek,
                payload: &[u8],
                iv: Vec<u8>,
                aad: Vec<u8>,
            ) -> Result<EncryptionResult, Error> {
                Self::encrypt_inner(&cek.value, payload, iv, aad)
            }

            fn decrypt(cek: &Self::Cek, res: &EncryptionResult) -> Result<Vec<u8>, Error> {
                let EncryptionResult {
                    nonce,
                    encrypted,
                    tag,
                    additional_data: aad,
                } = res;
                Self::decrypt_inner(&cek.value, &encrypted, &nonce, &tag, &aad)
            }
        }
    };
}

aes_gcm!(A128GCM, aes::Aes128, 128 / 8);
aes_gcm!(A192GCM, aes::Aes192, 192 / 8);
aes_gcm!(A256GCM, aes::Aes256, 256 / 8);

fn from_slice<Size: ArrayLength<u8>>(x: &[u8]) -> Result<&GenericArray<u8, Size>, Error> {
    if x.len() != Size::to_usize() {
        Err(Error::UnspecifiedCryptographicError)
    } else {
        Ok(GenericArray::from_slice(x))
    }
}

#[cfg(test)]
mod tests {
    use crate::test::random_vec;

    use super::*;

    /// `ContentEncryptionAlgorithm::A128GCM` generates CEK of the right length
    #[test]
    fn aes128gcm_key_length() {
        assert_eq!(A128GCM::generate_cek().as_bytes().len(), 128 / 8);
    }

    /// `ContentEncryptionAlgorithm::A192GCM` generates CEK of the right length
    #[test]
    fn aes192gcm_key_length() {
        assert_eq!(A192GCM::generate_cek().as_bytes().len(), 192 / 8);
    }

    /// `ContentEncryptionAlgorithm::A256GCM` generates CEK of the right length
    #[test]
    fn aes256gcm_key_length() {
        assert_eq!(A256GCM::generate_cek().as_bytes().len(), 256 / 8);
    }

    pub fn nonce() -> Vec<u8> {
        random_vec(12)
    }

    #[test]
    fn aes_gcm_128_encryption_round_trip_fixed_key_nonce() {
        let payload = "这个世界值得我们奋战！";
        let key = OctetKey::new(vec![0; 128 / 8]);
        cea_round_trip::<A128GCM>(&key, payload.as_bytes(), vec![0; 12], nonce());
    }

    #[test]
    fn aes_gcm_128_encryption_round_trip() {
        let payload = "这个世界值得我们奋战！";
        let key = OctetKey::new(random_vec(128 / 8));

        cea_round_trip::<A128GCM>(&key, payload.as_bytes(), vec![0; 12], nonce());
    }

    #[test]
    fn aes_gcm_192_encryption_round_trip_fixed_key_nonce() {
        let payload = "这个世界值得我们奋战！";
        let key = OctetKey::new(vec![0; 192 / 8]);
        cea_round_trip::<A192GCM>(&key, payload.as_bytes(), vec![0; 12], nonce());
    }

    #[test]
    fn aes_gcm_192_encryption_round_trip() {
        let payload = "这个世界值得我们奋战！";
        let key = OctetKey::new(random_vec(192 / 8));

        cea_round_trip::<A192GCM>(&key, payload.as_bytes(), vec![0; 12], nonce());
    }

    #[test]
    fn aes_gcm_256_encryption_round_trip_fixed_key_nonce() {
        let payload = "这个世界值得我们奋战！";
        let key = OctetKey::new(vec![0; 256 / 8]);

        cea_round_trip::<A256GCM>(&key, payload.as_bytes(), vec![0; 12], nonce());
    }

    #[test]
    fn aes_gcm_256_encryption_round_trip() {
        let payload = "这个世界值得我们奋战！";
        let key = OctetKey::new(random_vec(256 / 8));

        cea_round_trip::<A256GCM>(&key, payload.as_bytes(), vec![0; 12], nonce());
    }

    fn cea_round_trip<C: CEA>(key: &C::Cek, payload: &[u8], iv: Vec<u8>, aad: Vec<u8>)
    where
        C::Cek: Clone + PartialEq + std::fmt::Debug,
    {
        let res = C::encrypt(key, payload, iv, aad).unwrap();
        let output = C::decrypt(key, &res).unwrap();
        assert_ne!(res.encrypted, payload);
        assert_eq!(output, payload);
    }
}
