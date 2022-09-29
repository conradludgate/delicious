use std::marker::PhantomData;

use crate::{
    errors::Error,
    jwa::{EncryptionResult, OctetKey},
};

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
pub struct AesGcmKw<AES>(PhantomData<AES>);

#[allow(non_camel_case_types)]
/// Key wrapping with AES GCM using 128-bit key
pub type A128GCMKW = AesGcmKw<aes_gcm::Aes128Gcm>;
#[allow(non_camel_case_types)]
/// Key wrapping with AES GCM using 256-bit key
pub type A256GCMKW = AesGcmKw<aes_gcm::Aes256Gcm>;

#[allow(non_camel_case_types)]
pub struct AES_GCM_Header {
    nonce: Vec<u8>,
    tag: Vec<u8>,
}

use crate::jwa::cea::AesGcm;

macro_rules! aes_gcm {
    ($id:ident, $aes:ty, $name:literal) => {
        impl KMA for $id {
            const ALG: &'static str = $name;
            type Key = OctetKey;
            type Cek = OctetKey;
            type AlgorithmHeader = AES_GCM_Header;
            type WrapSettings = Vec<u8>;

            fn wrap(
                cek: Self::Cek,
                key: &Self::Key,
                settings: Self::WrapSettings,
            ) -> Result<(Vec<u8>, Self::AlgorithmHeader), Error> {
                let res = AesGcm::<$aes>::encrypt_inner(&key.0, cek.0, settings, Vec::new())?;
                let header = AES_GCM_Header {
                    nonce: res.nonce,
                    tag: res.tag,
                };
                Ok((res.encrypted, header))
            }

            fn unwrap(
                encrypted_cek: &[u8],
                key: &Self::Key,
                header: Self::AlgorithmHeader,
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

aes_gcm!(A128GCMKW, aes_gcm::Aes128Gcm, "A128GCMKW");
aes_gcm!(A256GCMKW, aes_gcm::Aes256Gcm, "A256GCMKW");

// fn from_slice<Size: ArrayLength<u8>>(x: &[u8]) -> Result<&GenericArray<u8, Size>, Error> {
//     if x.len() != Size::to_usize() {
//         Err(Error::UnspecifiedCryptographicError)
//     } else {
//         Ok(GenericArray::from_slice(x))
//     }
// }

impl From<AES_GCM> for super::Algorithm {
    fn from(a: AES_GCM) -> Self {
        super::Algorithm::AES_GCM_KW(a)
    }
}

impl AES_GCM {
    pub(crate) fn aes_gcm_encrypt(
        self,
        payload: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<EncryptionResult, Error> {
        use AES_GCM::{A128, A256};

        let cek = OctetKey(payload.to_vec());
        let key = OctetKey(key.to_vec());
        let nonce = nonce.to_vec();
        let (cek, header) = match self {
            A128 => A128GCMKW::wrap(cek, &key, nonce)?,
            A256 => A256GCMKW::wrap(cek, &key, nonce)?,
            _ => Err(Error::UnsupportedOperation)?,
        };

        Ok(EncryptionResult {
            nonce: header.nonce,
            encrypted: cek,
            tag: header.tag,
            additional_data: Vec::new(),
        })
    }

    pub(crate) fn aes_gcm_decrypt(
        self,
        encrypted: &EncryptionResult,
        key: &[u8],
    ) -> Result<Vec<u8>, Error> {
        use AES_GCM::{A128, A256};

        let key = OctetKey(key.to_vec());
        let header = AES_GCM_Header {
            tag: encrypted.tag.to_owned(),
            nonce: encrypted.nonce.to_owned(),
        };
        let cek = match self {
            A128 => A128GCMKW::unwrap(&encrypted.encrypted, &key, header)?.0,
            A256 => A256GCMKW::unwrap(&encrypted.encrypted, &key, header)?.0,
            _ => Err(Error::UnsupportedOperation)?,
        };
        Ok(cek)
    }
}

#[cfg(test)]
mod tests {
    use ring::{
        constant_time::verify_slices_are_equal,
        rand::{SecureRandom, SystemRandom},
    };

    use crate::{
        jwa::{kma::Algorithm, random_aes_gcm_nonce},
        jwe::CekAlgorithmHeader,
        jwk,
    };

    use super::*;

    fn random_key(length: usize) -> Vec<u8> {
        let mut key: Vec<u8> = vec![0; length];
        SystemRandom::new().fill(&mut key).unwrap();
        key
    }

    #[test]
    fn aes128gcmkw_key_encryption_round_trip() {
        let mut key: Vec<u8> = vec![0; 128 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let key = jwk::Specified {
            common: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                key_type: Default::default(),
                value: key,
            }),
        };

        let nonce = random_aes_gcm_nonce().unwrap();

        let cek_alg = Algorithm::AES_GCM_KW(AES_GCM::A128);
        let cek = random_key(128 / 8);

        let mut header = CekAlgorithmHeader {
            nonce: Some(nonce),
            ..Default::default()
        };
        let encrypted_cek = not_err!(cek_alg.wrap_key(&cek, &key, &mut header));
        let decrypted_cek = not_err!(cek_alg.unwrap_key(&encrypted_cek, &mut header, &key));

        assert!(verify_slices_are_equal(&cek, decrypted_cek.octet_key().unwrap(),).is_ok());
    }

    #[test]
    fn aes256gcmkw_key_encryption_round_trip() {
        let mut key: Vec<u8> = vec![0; 256 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let key = jwk::Specified {
            common: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                key_type: Default::default(),
                value: key,
            }),
        };

        let nonce = random_aes_gcm_nonce().unwrap();

        let cek_alg = Algorithm::AES_GCM_KW(AES_GCM::A256);
        let cek = random_key(128 / 8);

        let mut header = CekAlgorithmHeader {
            nonce: Some(nonce),
            ..Default::default()
        };
        let encrypted_cek = not_err!(cek_alg.wrap_key(&cek, &key, &mut header));
        let decrypted_cek = not_err!(cek_alg.unwrap_key(&encrypted_cek, &mut header, &key));

        assert!(verify_slices_are_equal(&cek, decrypted_cek.octet_key().unwrap(),).is_ok());
    }
}
