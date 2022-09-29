use std::marker::PhantomData;

use aead::{
    generic_array::{ArrayLength, GenericArray},
    AeadInPlace, KeyInit,
};

use super::CEA;
use crate::{
    jwa::{EncryptionResult, OctetKey},
    Error,
};

/// [Content Encryption with AES GCM](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
///
/// See
/// * [`A128GCM`] - AES GCM using 128-bit key
/// * [`A256GCM`] - AES GCM using 256-bit key
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AesGcm<Aes>(PhantomData<Aes>);

#[allow(non_camel_case_types)]
/// [Content Encryption with AES GCM using 128-bit key](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
pub type A128GCM = AesGcm<aes_gcm::Aes128Gcm>;
#[allow(non_camel_case_types)]
/// [Content Encryption with AES GCM using 256-bit key](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
pub type A256GCM = AesGcm<aes_gcm::Aes256Gcm>;

macro_rules! aes_gcm {
    ($id:ident, $aes:ty, $name:ident, $key_len:expr) => {
        impl $id {
            pub(crate) fn encrypt_inner(
                cek: &[u8],
                payload: &[u8],
                iv: Vec<u8>,
                aad: Vec<u8>,
            ) -> Result<EncryptionResult, Error> {
                let cipher = <$aes>::new_from_slice(&cek)?;
                let nonce: &aes_gcm::Nonce<_> = from_slice(&iv)?;
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
                let cipher = <$aes>::new_from_slice(&cek)?;
                let nonce: &aes_gcm::Nonce<_> = from_slice(&nonce)?;
                let tag: &aes_gcm::Tag = from_slice(&tag)?;
                let mut in_out: Vec<u8> = encrypted.to_vec();
                cipher
                    .decrypt_in_place_detached(nonce, &aad, &mut in_out, tag)
                    .map_err(|_| Error::UnspecifiedCryptographicError)?;
                Ok(in_out)
            }
        }

        impl CEA for $id {
            const ENC: super::super::ContentEncryptionAlgorithm =
                super::super::ContentEncryptionAlgorithm::$name;
            type Cek = OctetKey;
            const IV: usize = 96 / 8;

            fn generate_cek() -> Self::Cek {
                let mut rng = rand::thread_rng();
                let mut key = vec![0; $key_len];
                rand::Rng::fill(&mut rng, key.as_mut_slice());
                OctetKey(key)
            }

            fn encrypt(
                cek: &Self::Cek,
                payload: &[u8],
                iv: Vec<u8>,
                aad: Vec<u8>,
            ) -> Result<EncryptionResult, Error> {
                Self::encrypt_inner(&cek.0, payload, iv, aad)
            }

            fn decrypt(cek: &Self::Cek, res: &EncryptionResult) -> Result<Vec<u8>, Error> {
                let EncryptionResult {
                    nonce,
                    encrypted,
                    tag,
                    additional_data: aad,
                } = res;
                Self::decrypt_inner(&cek.0, &encrypted, &nonce, &tag, &aad)
            }
        }
    };
}

aes_gcm!(A128GCM, aes_gcm::Aes128Gcm, A128GCM, 128 / 8);
aes_gcm!(A256GCM, aes_gcm::Aes256Gcm, A256GCM, 256 / 8);

fn from_slice<Size: ArrayLength<u8>>(x: &[u8]) -> Result<&GenericArray<u8, Size>, Error> {
    if x.len() != Size::to_usize() {
        Err(Error::UnspecifiedCryptographicError)
    } else {
        Ok(GenericArray::from_slice(x))
    }
}

#[cfg(test)]
mod tests {
    use ring::rand::{SecureRandom, SystemRandom};

    use super::*;

    #[test]
    fn aes_gcm_128_encryption_round_trip_fixed_key_nonce() {
        let payload = "这个世界值得我们奋战！";
        let key = OctetKey(vec![0; 128 / 8]);
        cea_round_trip::<A128GCM>(&key, payload.as_bytes(), vec![0; 12], vec![]);
    }

    #[test]
    fn aes_gcm_128_encryption_round_trip() {
        let payload = "这个世界值得我们奋战！";
        let mut key = OctetKey(vec![0; 128 / 8]);
        SystemRandom::new().fill(&mut key.0).unwrap();

        cea_round_trip::<A128GCM>(&key, payload.as_bytes(), vec![0; 12], vec![]);
    }

    #[test]
    fn aes_gcm_256_encryption_round_trip_fixed_key_nonce() {
        let payload = "这个世界值得我们奋战！";
        let key = OctetKey(vec![0; 256 / 8]);

        cea_round_trip::<A256GCM>(&key, payload.as_bytes(), vec![0; 12], vec![]);
    }

    #[test]
    fn aes_gcm_256_encryption_round_trip() {
        let payload = "这个世界值得我们奋战！";
        let mut key = OctetKey(vec![0; 256 / 8]);
        SystemRandom::new().fill(&mut key.0).unwrap();

        cea_round_trip::<A256GCM>(&key, payload.as_bytes(), vec![0; 12], vec![]);
    }

    fn cea_round_trip<C: CEA>(key: &C::Cek, payload: &[u8], iv: Vec<u8>, aad: Vec<u8>)
    where
        C::Cek: Clone + PartialEq + std::fmt::Debug,
    {
        let res = C::encrypt(key, payload, iv, aad).unwrap();
        let output = C::decrypt(key, &res).unwrap();
        assert_eq!(output, payload);
    }
}
