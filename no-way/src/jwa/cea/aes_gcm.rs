use std::marker::PhantomData;

use aead::{
    generic_array::{ArrayLength, GenericArray},
    AeadInPlace, KeyInit,
};

use super::{EncryptionResult, CEA};
use crate::Error;

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

/// [Content Encryption with AES GCM using 128-bit key](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
pub type A128GCM = AesGcm<aes::Aes128>;

/// [Content Encryption with AES GCM using 192-bit key](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
pub type A192GCM = AesGcm<aes::Aes192>;

/// [Content Encryption with AES GCM using 256-bit key](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
pub type A256GCM = AesGcm<aes::Aes256>;

macro_rules! aes_gcm {
    ($id:ident, $aes:ty, $key_len:expr) => {
        impl $id {
            pub(crate) fn encrypt_inner(
                cek: &[u8],
                payload: &[u8],
                iv: &[u8],
                aad: &[u8],
            ) -> Result<EncryptionResult, Error> {
                let mut output = EncryptionResult::from([aad, iv, payload, &[0; 16]]);

                let cipher =
                    ::aes_gcm::AesGcm::<$aes, aes::cipher::consts::U12>::new_from_slice(&cek)?;

                let [aad, iv, payload, tag] = output.split_mut();

                let nonce: &::aes_gcm::Nonce<_> = from_slice(&iv)?;
                let t = cipher
                    .encrypt_in_place_detached(nonce, &aad, payload)
                    .map_err(|_| Error::UnspecifiedCryptographicError)?;

                tag.copy_from_slice(&t);

                Ok(output)
            }

            pub(crate) fn decrypt_inner<'r>(
                cek: &[u8],
                encrypted: &'r mut [u8],
                nonce: &[u8],
                tag: &[u8],
                aad: &[u8],
            ) -> Result<&'r [u8], Error> {
                let cipher =
                    ::aes_gcm::AesGcm::<$aes, aes::cipher::consts::U12>::new_from_slice(&cek)?;
                let nonce: &::aes_gcm::Nonce<_> = from_slice(&nonce)?;
                let tag: &::aes_gcm::Tag = from_slice(&tag)?;
                cipher
                    .decrypt_in_place_detached(nonce, &aad, encrypted, tag)
                    .map_err(|_| Error::UnspecifiedCryptographicError)?;
                Ok(encrypted)
            }
        }

        impl CEA for $id {
            const ENC: super::Algorithm = super::Algorithm::$id;
            const IV: usize = 96 / 8;

            fn generate_cek() -> Vec<u8> {
                let mut rng = rand::thread_rng();
                let mut key = vec![0; $key_len];
                rand::Rng::fill(&mut rng, key.as_mut_slice());
                key
            }

            fn encrypt(
                cek: &[u8],
                payload: &[u8],
                iv: &[u8],
                aad: &[u8],
            ) -> Result<EncryptionResult, Error> {
                Self::encrypt_inner(&cek, payload, iv, aad)
            }

            fn decrypt<'r>(cek: &[u8], res: &'r mut EncryptionResult) -> Result<&'r [u8], Error> {
                let [aad, iv, payload, tag] = res.split_mut();
                Self::decrypt_inner(&cek, payload, iv, tag, aad)
            }
        }
    };
}

aes_gcm!(A128GCM, aes::Aes128, 128 / 8);
aes_gcm!(A192GCM, aes::Aes192, 192 / 8);
aes_gcm!(A256GCM, aes::Aes256, 256 / 8);

fn from_slice<Size: ArrayLength<u8>>(x: &[u8]) -> Result<&GenericArray<u8, Size>, Error> {
    if x.len() == Size::to_usize() {
        Ok(GenericArray::from_slice(x))
    } else {
        Err(Error::UnspecifiedCryptographicError)
    }
}

#[cfg(test)]
mod tests {
    use crate::test::random_vec;

    use super::*;

    /// `ContentEncryptionAlgorithm::A128GCM` generates CEK of the right length
    #[test]
    fn aes128gcm_key_length() {
        assert_eq!(A128GCM::generate_cek().len(), 128 / 8);
    }

    /// `ContentEncryptionAlgorithm::A192GCM` generates CEK of the right length
    #[test]
    fn aes192gcm_key_length() {
        assert_eq!(A192GCM::generate_cek().len(), 192 / 8);
    }

    /// `ContentEncryptionAlgorithm::A256GCM` generates CEK of the right length
    #[test]
    fn aes256gcm_key_length() {
        assert_eq!(A256GCM::generate_cek().len(), 256 / 8);
    }

    pub fn nonce() -> Vec<u8> {
        random_vec(12)
    }

    #[test]
    fn aes_gcm_128_encryption_round_trip_fixed_key_nonce() {
        let payload = "这个世界值得我们奋战！";
        let key = vec![0; 128 / 8];
        cea_round_trip::<A128GCM>(&key, payload.as_bytes(), &nonce(), &nonce());
    }

    #[test]
    fn aes_gcm_128_encryption_round_trip() {
        let payload = "这个世界值得我们奋战！";
        let key = random_vec(128 / 8);

        cea_round_trip::<A128GCM>(&key, payload.as_bytes(), &nonce(), &nonce());
    }

    #[test]
    fn aes_gcm_192_encryption_round_trip_fixed_key_nonce() {
        let payload = "这个世界值得我们奋战！";
        let key = vec![0; 192 / 8];
        cea_round_trip::<A192GCM>(&key, payload.as_bytes(), &nonce(), &nonce());
    }

    #[test]
    fn aes_gcm_192_encryption_round_trip() {
        let payload = "这个世界值得我们奋战！";
        let key = random_vec(192 / 8);

        cea_round_trip::<A192GCM>(&key, payload.as_bytes(), &nonce(), &nonce());
    }

    #[test]
    fn aes_gcm_256_encryption_round_trip_fixed_key_nonce() {
        let payload = "这个世界值得我们奋战！";
        let key = vec![0; 256 / 8];

        cea_round_trip::<A256GCM>(&key, payload.as_bytes(), &nonce(), &nonce());
    }

    #[test]
    fn aes_gcm_256_encryption_round_trip() {
        let payload = "这个世界值得我们奋战！";
        let key = random_vec(256 / 8);

        cea_round_trip::<A256GCM>(&key, payload.as_bytes(), &nonce(), &nonce());
    }

    fn cea_round_trip<C: CEA>(key: &[u8], payload: &[u8], iv: &[u8], aad: &[u8]) {
        let mut res = C::encrypt(key, payload, iv, aad).unwrap();
        assert_ne!(&res[2], payload);
        let output = C::decrypt(key, &mut res).unwrap();
        assert_eq!(output, payload);
    }
}
