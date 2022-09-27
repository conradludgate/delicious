use crate::{errors::Error, jwa::EncryptionResult, jwk};
use ring::aead;

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

        let algorithm = match self {
            A128 => &aead::AES_128_GCM,
            A256 => &aead::AES_256_GCM,
            _ => Err(Error::UnsupportedOperation)?,
        };

        aes_gcm_encrypt(algorithm, payload, nonce, &[], key)
    }

    pub(crate) fn aes_gcm_decrypt(
        self,
        encrypted: &EncryptionResult,
        key: &[u8],
    ) -> Result<jwk::JWK<()>, Error> {
        use AES_GCM::{A128, A256};

        let algorithm = match self {
            A128 => &aead::AES_128_GCM,
            A256 => &aead::AES_256_GCM,
            _ => Err(Error::UnsupportedOperation)?,
        };

        let cek = aes_gcm_decrypt(algorithm, encrypted, key)?;
        Ok(jwk::JWK {
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                value: cek,
                key_type: Default::default(),
            }),
            common: jwk::CommonParameters {
                public_key_use: Some(jwk::PublicKeyUse::Encryption),
                algorithm: None,
                ..Default::default()
            },
            additional: Default::default(),
        })
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

        let key = jwk::JWK::<()> {
            common: Default::default(),
            additional: Default::default(),
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

        let key = jwk::JWK::<()> {
            common: Default::default(),
            additional: Default::default(),
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
