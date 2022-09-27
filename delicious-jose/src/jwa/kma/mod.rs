use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{errors::Error, jwa::EncryptionResult, jwe::CekAlgorithmHeader, jwk, Empty};

use super::{Algorithm, ContentEncryptionAlgorithm};

pub mod aes_gcm;
pub mod pbes2_aes_kw;
use pbes2_aes_kw::{KeyManagementAlgorithmPBES2, PBES2};

/// Algorithms for key management as defined in [RFC7518#4](https://tools.ietf.org/html/rfc7518#section-4)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum KeyManagementAlgorithm {
    /// RSAES-PKCS1-v1_5
    RSA1_5,
    /// RSAES OAEP using default parameters
    #[serde(rename = "RSA-OAEP")]
    RSA_OAEP,
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    #[serde(rename = "RSA-OAEP-256")]
    RSA_OAEP_256,
    /// AES Key Wrap using 128-bit key. _Unsupported_
    A128KW,
    /// AES Key Wrap using 192-bit key. _Unsupported_.
    /// This is [not supported](https://github.com/briansmith/ring/issues/112) by `ring`.
    A192KW,
    /// AES Key Wrap using 256-bit key. _Unsupported_
    A256KW,
    /// Direct use of a shared symmetric key
    #[serde(rename = "dir")]
    DirectSymmetricKey,
    /// ECDH-ES using Concat KDF
    #[serde(rename = "ECDH-ES")]
    ECDH_ES,
    /// ECDH-ES using Concat KDF and "A128KW" wrapping
    #[serde(rename = "ECDH-ES+A128KW")]
    ECDH_ES_A128KW,
    /// ECDH-ES using Concat KDF and "A192KW" wrapping
    #[serde(rename = "ECDH-ES+A192KW")]
    ECDH_ES_A192KW,
    /// ECDH-ES using Concat KDF and "A256KW" wrapping
    #[serde(rename = "ECDH-ES+A256KW")]
    ECDH_ES_A256KW,
    /// Key wrapping with AES GCM using 128-bit key alg
    A128GCMKW,
    /// Key wrapping with AES GCM using 192-bit key alg.
    /// This is [not supported](https://github.com/briansmith/ring/issues/112) by `ring`.
    A192GCMKW,
    /// Key wrapping with AES GCM using 256-bit key alg
    A256GCMKW,
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    #[serde(rename = "PBES2-HS256+A128KW")]
    PBES2_HS256_A128KW,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    #[serde(rename = "PBES2-HS384+A192KW")]
    PBES2_HS384_A192KW,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    #[serde(rename = "PBES2-HS512+A256KW")]
    PBES2_HS512_A256KW,
}

impl Default for KeyManagementAlgorithm {
    fn default() -> Self {
        KeyManagementAlgorithm::DirectSymmetricKey
    }
}

// /// Algorithms for key management as defined in [RFC7518#4.7](https://tools.ietf.org/html/rfc7518#section-4.7)
// #[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
// #[allow(non_camel_case_types)]
// pub enum KeyManagementAlgorithmAESGCM {
//     /// Key wrapping with AES GCM using 128-bit key alg
//     A128GCMKW,
//     /// Key wrapping with AES GCM using 192-bit key alg.
//     /// This is [not supported](https://github.com/briansmith/ring/issues/112) by `ring`.
//     A192GCMKW,
//     /// Key wrapping with AES GCM using 256-bit key alg
//     A256GCMKW,
// }

// /// Algorithms for key management as defined in [RFC7518#4.7](https://tools.ietf.org/html/rfc7518#section-4.7)
// #[allow(non_camel_case_types)]
// pub struct AESGCM {
//     pub kma: KeyManagementAlgorithmAESGCM,
//     pub iv: Vec<u8>,
//     pub tag: Vec<u8>,
// }

/// Describes the type of operations that the key management algorithm
/// supports with respect to a Content Encryption Key (CEK)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum KeyManagementAlgorithmType {
    /// Wraps a randomly generated CEK using a symmetric encryption algorithm
    SymmetricKeyWrapping,
    /// Encrypt a randomly generated CEK using an asymmetric encryption algorithm,
    AsymmetricKeyEncryption,
    /// A key agreement algorithm to pick a CEK
    DirectKeyAgreement,
    /// A key agreement algorithm used to pick a symmetric CEK and wrap the CEK with a symmetric encryption algorithm
    KeyAgreementWithKeyWrapping,
    /// A user defined symmetric shared key is the CEK
    DirectEncryption,
}

impl KeyManagementAlgorithm {
    /// Returns the type of operations that the algorithm is intended to support
    pub fn algorithm_type(self) -> KeyManagementAlgorithmType {
        use self::KeyManagementAlgorithm::*;

        match self {
            A128KW | A192KW | A256KW | A128GCMKW | A192GCMKW | A256GCMKW | PBES2_HS256_A128KW
            | PBES2_HS384_A192KW | PBES2_HS512_A256KW => {
                KeyManagementAlgorithmType::SymmetricKeyWrapping
            }
            RSA1_5 | RSA_OAEP | RSA_OAEP_256 => KeyManagementAlgorithmType::AsymmetricKeyEncryption,
            DirectSymmetricKey => KeyManagementAlgorithmType::DirectEncryption,
            ECDH_ES => KeyManagementAlgorithmType::DirectKeyAgreement,
            ECDH_ES_A128KW | ECDH_ES_A192KW | ECDH_ES_A256KW => {
                KeyManagementAlgorithmType::KeyAgreementWithKeyWrapping
            }
        }
    }

    /// Return the Content Encryption Key (CEK) based on the key management algorithm
    ///
    /// If the algorithm is `dir` or `DirectSymmetricKey`, the key provided is the CEK.
    /// Otherwise, the appropriate algorithm will be used to derive or generate the required CEK
    /// using the provided key.
    pub fn cek<T>(
        self,
        content_alg: ContentEncryptionAlgorithm,
        key: &jwk::JWK<T>,
    ) -> Result<jwk::JWK<Empty>, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        use self::KeyManagementAlgorithm::{DirectSymmetricKey, A128GCMKW, A256GCMKW};

        match self {
            DirectSymmetricKey => Self::cek_direct(key),
            A128GCMKW | A256GCMKW => Self::cek_aes_gcm(content_alg),
            // PBES2_HS256_A128KW | PBES2_HS384_A192KW | PBES2_HS512_A256KW => Self::cek_pbes2(key),
            _ => Err(Error::UnsupportedOperation),
        }
    }

    fn cek_direct<T>(key: &jwk::JWK<T>) -> Result<jwk::JWK<Empty>, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        match key.key_type() {
            jwk::KeyType::Octet => Ok(key.clone_without_additional()),
            others => Err(unexpected_key_type_error!(jwk::KeyType::Octet, others)),
        }
    }

    fn cek_aes_gcm(content_alg: ContentEncryptionAlgorithm) -> Result<jwk::JWK<Empty>, Error> {
        let key = content_alg.generate_key()?;
        Ok(jwk::JWK {
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                value: key,
                key_type: Default::default(),
            }),
            common: jwk::CommonParameters {
                public_key_use: Some(jwk::PublicKeyUse::Encryption),
                algorithm: Some(Algorithm::ContentEncryption(content_alg)),
                ..Default::default()
            },
            additional: Default::default(),
        })
    }

    /// Encrypt or wrap a Content Encryption Key with the provided algorithm
    pub fn wrap_key<T: Serialize + DeserializeOwned>(
        self,
        payload: &[u8],
        key: &jwk::JWK<T>,
        header: &mut CekAlgorithmHeader,
    ) -> Result<Vec<u8>, Error> {
        use self::KeyManagementAlgorithm::{
            DirectSymmetricKey, A128GCMKW, A192GCMKW, A256GCMKW, PBES2_HS256_A128KW,
            PBES2_HS384_A192KW, PBES2_HS512_A256KW,
        };

        match self {
            A128GCMKW | A192GCMKW | A256GCMKW => {
                let nonce = header.nonce.as_deref().ok_or(Error::UnsupportedOperation)?;
                let encrypted = self.aes_gcm_encrypt(payload, key.algorithm.octet_key()?, nonce)?;
                header.tag = Some(encrypted.tag);
                Ok(encrypted.encrypted)
            }
            PBES2_HS256_A128KW => {
                let key = key.algorithm.octet_key()?;
                PBES2 {
                    kma: KeyManagementAlgorithmPBES2::PBES2_HS256_A128KW,
                    salt: header.salt.clone().ok_or(Error::UnsupportedOperation)?,
                    count: header.count.unwrap_or_default(),
                }
                .encrypt(payload, key)
            }
            PBES2_HS384_A192KW => {
                let key = key.algorithm.octet_key()?;
                PBES2 {
                    kma: KeyManagementAlgorithmPBES2::PBES2_HS384_A192KW,
                    salt: header.salt.take().unwrap_or_default(),
                    count: header.count.take().unwrap_or_default(),
                }
                .encrypt(payload, key)
            }
            PBES2_HS512_A256KW => {
                let key = key.algorithm.octet_key()?;
                PBES2 {
                    kma: KeyManagementAlgorithmPBES2::PBES2_HS512_A256KW,
                    salt: header.salt.take().unwrap_or_default(),
                    count: header.count.take().unwrap_or_default(),
                }
                .encrypt(payload, key)
            }
            DirectSymmetricKey => Ok(Vec::new()),
            _ => Err(Error::UnsupportedOperation),
        }
    }

    /// Decrypt or unwrap a CEK with the provided algorithm
    pub fn unwrap_key<T: Serialize + DeserializeOwned>(
        self,
        encrypted: &[u8],
        header: &mut CekAlgorithmHeader,
        key: &jwk::JWK<T>,
    ) -> Result<jwk::JWK<Empty>, Error> {
        use self::KeyManagementAlgorithm::{
            DirectSymmetricKey, A128GCMKW, A192GCMKW, A256GCMKW, PBES2_HS256_A128KW,
            PBES2_HS384_A192KW, PBES2_HS512_A256KW,
        };

        match self {
            A128GCMKW | A192GCMKW | A256GCMKW => {
                let key = key.algorithm.octet_key()?;

                self.aes_gcm_decrypt(
                    &EncryptionResult {
                        encrypted: encrypted.to_vec(),
                        nonce: header.nonce.take().unwrap_or_default(),
                        tag: header.tag.take().unwrap_or_default(),
                        ..Default::default()
                    },
                    key,
                )
            }
            PBES2_HS256_A128KW => {
                let key = key.algorithm.octet_key()?;
                PBES2 {
                    kma: KeyManagementAlgorithmPBES2::PBES2_HS256_A128KW,
                    salt: header.salt.take().unwrap_or_default(),
                    count: header.count.take().unwrap_or_default(),
                }
                .decrypt(encrypted, key)
            }
            PBES2_HS384_A192KW => {
                let key = key.algorithm.octet_key()?;
                PBES2 {
                    kma: KeyManagementAlgorithmPBES2::PBES2_HS384_A192KW,
                    salt: header.salt.take().unwrap_or_default(),
                    count: header.count.take().unwrap_or_default(),
                }
                .decrypt(encrypted, key)
            }
            PBES2_HS512_A256KW => {
                let key = key.algorithm.octet_key()?;
                PBES2 {
                    kma: KeyManagementAlgorithmPBES2::PBES2_HS512_A256KW,
                    salt: header.salt.take().unwrap_or_default(),
                    count: header.count.take().unwrap_or_default(),
                }
                .decrypt(encrypted, key)
            }
            DirectSymmetricKey => Ok(key.clone_without_additional()),
            _ => Err(Error::UnsupportedOperation),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        constant_time::verify_slices_are_equal,
        rand::{SecureRandom, SystemRandom},
    };

    use crate::{jwa, jwk, Empty};

    /// `KeyManagementAlgorithm::DirectSymmetricKey` returns the same key when CEK is requested
    #[test]
    fn dir_cek_returns_provided_key() {
        let mut key: Vec<u8> = vec![0; 256 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let key = jwk::JWK::<Empty> {
            common: Default::default(),
            additional: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                key_type: Default::default(),
                value: key,
            }),
        };

        let cek_alg = KeyManagementAlgorithm::DirectSymmetricKey;
        let cek = not_err!(cek_alg.cek(jwa::ContentEncryptionAlgorithm::A256GCM, &key));

        assert!(
            verify_slices_are_equal(cek.octet_key().unwrap(), key.octet_key().unwrap()).is_ok()
        );
    }

    /// `KeyManagementAlgorithm::A128GCMKW` returns a random key with the right length when CEK is requested
    #[test]
    fn cek_aes128gcmkw_returns_right_key_length() {
        let mut key: Vec<u8> = vec![0; 128 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let key = jwk::JWK::<Empty> {
            common: Default::default(),
            additional: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                key_type: Default::default(),
                value: key,
            }),
        };

        let cek_alg = KeyManagementAlgorithm::A128GCMKW;
        let cek = not_err!(cek_alg.cek(jwa::ContentEncryptionAlgorithm::A128GCM, &key));
        assert_eq!(cek.octet_key().unwrap().len(), 128 / 8);
        assert!(
            verify_slices_are_equal(cek.octet_key().unwrap(), key.octet_key().unwrap()).is_err()
        );

        let cek = not_err!(cek_alg.cek(jwa::ContentEncryptionAlgorithm::A256GCM, &key));
        assert_eq!(cek.octet_key().unwrap().len(), 256 / 8);
        assert!(
            verify_slices_are_equal(cek.octet_key().unwrap(), key.octet_key().unwrap()).is_err()
        );
    }

    /// `KeyManagementAlgorithm::A256GCMKW` returns a random key with the right length when CEK is requested
    #[test]
    fn cek_aes256gcmkw_returns_right_key_length() {
        let mut key: Vec<u8> = vec![0; 256 / 8];
        not_err!(SystemRandom::new().fill(&mut key));

        let key = jwk::JWK::<Empty> {
            common: Default::default(),
            additional: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                key_type: Default::default(),
                value: key,
            }),
        };

        let cek_alg = KeyManagementAlgorithm::A256GCMKW;
        let cek = not_err!(cek_alg.cek(jwa::ContentEncryptionAlgorithm::A128GCM, &key));
        assert_eq!(cek.octet_key().unwrap().len(), 128 / 8);
        assert!(
            verify_slices_are_equal(cek.octet_key().unwrap(), key.octet_key().unwrap()).is_err()
        );

        let cek = not_err!(cek_alg.cek(jwa::ContentEncryptionAlgorithm::A256GCM, &key));
        assert_eq!(cek.octet_key().unwrap().len(), 256 / 8);
        assert!(
            verify_slices_are_equal(cek.octet_key().unwrap(), key.octet_key().unwrap()).is_err()
        );
    }
}
