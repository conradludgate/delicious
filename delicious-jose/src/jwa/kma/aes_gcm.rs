use crate::{errors::Error, jwa::EncryptionResult};
use ::aead::{AeadInPlace, KeyInit, generic_array::{GenericArray, ArrayLength}};
use ring::aead;

use super::{OctetKey, KMA};

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
pub struct A128GCMKW;
#[allow(non_camel_case_types)]
pub struct A256GCMKW;

// trait AES_GCM {

// }

#[allow(non_camel_case_types)]
pub struct AES_GCM_Header {
    nonce: Vec<u8>,
    tag: Vec<u8>,
}

impl KMA for A128GCMKW {
    type Key = OctetKey;
    type Cek = OctetKey;
    type AlgorithmHeader = AES_GCM_Header;
    type WrapSettings = Vec<u8>;

    fn wrap(
        cek: Self::Cek,
        key: &Self::Key,
        settings: Self::WrapSettings,
    ) -> Result<(Vec<u8>, Self::AlgorithmHeader), Error> {
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key.0)?;
        let nonce = aes_gcm::Nonce::from_slice(&settings);
        let mut in_out: Vec<u8> = cek.0;
        let tag = cipher
            .encrypt_in_place_detached(nonce, &[], &mut in_out)
            .map_err(|_| Error::UnspecifiedCryptographicError)?;

        let header = AES_GCM_Header {
            nonce: settings,
            tag: tag.to_vec(),
        };
        Ok((in_out, header))
    }

    fn unwrap(
        encrypted_cek: &[u8],
        key: &Self::Key,
        header: Self::AlgorithmHeader,
    ) -> Result<Self::Cek, Error> {
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key.0)?;
        let nonce = aes_gcm::Nonce::from_slice(&header.nonce);
        let tag = aes_gcm::Tag::from_slice(&header.tag);
        let mut in_out: Vec<u8> = encrypted_cek.to_vec();
        cipher
            .decrypt_in_place_detached(nonce, &[], &mut in_out, tag)
            .map_err(|_| Error::UnspecifiedCryptographicError)?;

        Ok(OctetKey(in_out))
    }
}

impl KMA for A256GCMKW {
    type Key = OctetKey;
    type Cek = OctetKey;
    type AlgorithmHeader = AES_GCM_Header;
    type WrapSettings = Vec<u8>;

    fn wrap(
        cek: Self::Cek,
        key: &Self::Key,
        settings: Self::WrapSettings,
    ) -> Result<(Vec<u8>, Self::AlgorithmHeader), Error> {
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key.0)?;
        let nonce = from_slice(&settings)?;
        let mut in_out: Vec<u8> = cek.0;
        let tag = cipher
            .encrypt_in_place_detached(nonce, &[], &mut in_out)
            .map_err(|_| Error::UnspecifiedCryptographicError)?;

        let header = AES_GCM_Header {
            nonce: settings,
            tag: tag.to_vec(),
        };
        Ok((in_out, header))
    }

    fn unwrap(
        encrypted_cek: &[u8],
        key: &Self::Key,
        header: Self::AlgorithmHeader,
    ) -> Result<Self::Cek, Error> {
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key.0)?;
        let nonce = from_slice(&header.nonce)?;
        let tag = from_slice(&header.tag)?;
        let mut in_out: Vec<u8> = encrypted_cek.to_vec();
        cipher
            .decrypt_in_place_detached(nonce, &[], &mut in_out, tag)
            .map_err(|_| Error::UnspecifiedCryptographicError)?;

        Ok(OctetKey(in_out))
    }
}

fn from_slice<Size: ArrayLength<u8>>(x: &[u8]) -> Result<&GenericArray<u8, Size>, Error> {
    if x.len() != Size::to_usize() {
        Err(Error::UnspecifiedCryptographicError)
    } else {
        Ok(GenericArray::from_slice(x))
    }
}

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

/// Encrypt a payload with AES GCM
pub(crate) fn aes_gcm_encrypt(
    algorithm: &'static aead::Algorithm,
    payload: &[u8],
    nonce: &[u8],
    aad: &[u8],
    key: &[u8],
) -> Result<EncryptionResult, Error> {
    let key = aead::UnboundKey::new(algorithm, key)?;
    let sealing_key = aead::LessSafeKey::new(key);

    let mut in_out: Vec<u8> = payload.to_vec();
    let tag = sealing_key.seal_in_place_separate_tag(
        aead::Nonce::try_assume_unique_for_key(nonce)?,
        aead::Aad::from(aad),
        &mut in_out,
    )?;

    Ok(EncryptionResult {
        nonce: nonce.to_vec(),
        encrypted: in_out,
        tag: tag.as_ref().to_vec(),
        additional_data: aad.to_vec(),
    })
}

/// Decrypts a payload with AES GCM
pub(crate) fn aes_gcm_decrypt(
    algorithm: &'static aead::Algorithm,
    encrypted: &EncryptionResult,
    key: &[u8],
) -> Result<Vec<u8>, Error> {
    let key = aead::UnboundKey::new(algorithm, key)?;
    let opening_key = aead::LessSafeKey::new(key);

    let mut in_out = encrypted.encrypted.clone();
    in_out.append(&mut encrypted.tag.clone());

    let nonce = aead::Nonce::try_assume_unique_for_key(&encrypted.nonce)?;
    let plaintext = opening_key.open_in_place(
        nonce,
        aead::Aad::from(&encrypted.additional_data),
        &mut in_out,
    )?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use ring::{
        constant_time::verify_slices_are_equal,
        rand::{SecureRandom, SystemRandom},
    };

    use crate::{
        jwa::{kma::Algorithm, random_aes_gcm_nonce, AES_GCM_NONCE_LENGTH},
        jwe::CekAlgorithmHeader,
        jwk,
    };

    use super::*;
    #[test]
    fn aes_gcm_128_encryption_round_trip_fixed_key_nonce() {
        const PAYLOAD: &str = "这个世界值得我们奋战！";
        let key: Vec<u8> = vec![0; 128 / 8];

        let encrypted = not_err!(aes_gcm_encrypt(
            &aead::AES_128_GCM,
            PAYLOAD.as_bytes(),
            &[0; AES_GCM_NONCE_LENGTH],
            &[],
            &key,
        ));
        let decrypted = not_err!(aes_gcm_decrypt(&aead::AES_128_GCM, &encrypted, &key));

        let payload = not_err!(String::from_utf8(decrypted));
        assert_eq!(payload, PAYLOAD);
    }

    #[test]
    fn aes_gcm_128_encryption_round_trip() {
        const PAYLOAD: &str = "这个世界值得我们奋战！";
        let mut key: Vec<u8> = vec![0; 128 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let encrypted = not_err!(aes_gcm_encrypt(
            &aead::AES_128_GCM,
            PAYLOAD.as_bytes(),
            &random_aes_gcm_nonce().unwrap(),
            &[],
            &key,
        ));
        let decrypted = not_err!(aes_gcm_decrypt(&aead::AES_128_GCM, &encrypted, &key));

        let payload = not_err!(String::from_utf8(decrypted));
        assert_eq!(payload, PAYLOAD);
    }

    #[test]
    fn aes_gcm_256_encryption_round_trip() {
        const PAYLOAD: &str = "这个世界值得我们奋战！";
        let mut key: Vec<u8> = vec![0; 256 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let encrypted = not_err!(aes_gcm_encrypt(
            &aead::AES_256_GCM,
            PAYLOAD.as_bytes(),
            &random_aes_gcm_nonce().unwrap(),
            &[],
            &key,
        ));
        let decrypted = not_err!(aes_gcm_decrypt(&aead::AES_256_GCM, &encrypted, &key));

        let payload = not_err!(String::from_utf8(decrypted));
        assert_eq!(payload, PAYLOAD);
    }

    #[test]
    fn aes_gcm_256_encryption_round_trip_fixed_key_nonce() {
        const PAYLOAD: &str = "这个世界值得我们奋战！";
        let key: Vec<u8> = vec![0; 256 / 8];

        let encrypted = not_err!(aes_gcm_encrypt(
            &aead::AES_256_GCM,
            PAYLOAD.as_bytes(),
            &[0; AES_GCM_NONCE_LENGTH],
            &[],
            &key,
        ));
        let decrypted = not_err!(aes_gcm_decrypt(&aead::AES_256_GCM, &encrypted, &key));

        let payload = not_err!(String::from_utf8(decrypted));
        assert_eq!(payload, PAYLOAD);
    }

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
