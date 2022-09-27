//! [Cryptographic Algorithms for Key Management](https://www.rfc-editor.org/rfc/rfc7518#section-4)

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{errors::Error, jwa::EncryptionResult, jwe::CekAlgorithmHeader, jwk, Empty};

use super::ContentEncryptionAlgorithm;

pub(crate) mod aes_gcm;
mod pbes2_aes_kw;

pub use aes_gcm::AES_GCM;
pub use pbes2_aes_kw::PBES2;

/// Algorithms for key management as defined in [RFC7518#4](https://tools.ietf.org/html/rfc7518#section-4)
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum Algorithm {
    /// RSAES-PKCS1-v1_5
    RSA1_5,
    /// RSAES OAEP using default parameters
    RSA_OAEP,
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    RSA_OAEP_256,
    /// AES Key Wrap using 128-bit key. _Unsupported_
    A128KW,
    /// AES Key Wrap using 192-bit key. _Unsupported_.
    /// This is [not supported](https://github.com/briansmith/ring/issues/112) by `ring`.
    A192KW,
    /// AES Key Wrap using 256-bit key. _Unsupported_
    A256KW,
    /// Direct use of a shared symmetric key
    DirectSymmetricKey,
    /// ECDH-ES using Concat KDF
    ECDH_ES,
    /// ECDH-ES using Concat KDF and "A128KW" wrapping
    ECDH_ES_A128KW,
    /// ECDH-ES using Concat KDF and "A192KW" wrapping
    ECDH_ES_A192KW,
    /// ECDH-ES using Concat KDF and "A256KW" wrapping
    ECDH_ES_A256KW,
    /// Key wrapping with AES GCM. [RFC7518#4.7](https://tools.ietf.org/html/rfc7518#section-4.7)
    AES_GCM_KW(AES_GCM),
    /// PBES2 with HMAC SHA and AES key-wrapping. [RFC7518#4.8](https://tools.ietf.org/html/rfc7518#section-4.8)
    PBES2(PBES2),
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::DirectSymmetricKey
    }
}

/// Describes the type of operations that the key management algorithm
/// supports with respect to a Content Encryption Key (CEK)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum AlgorithmType {
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

impl Algorithm {
    /// Returns the type of operations that the algorithm is intended to support
    pub fn algorithm_type(self) -> AlgorithmType {
        use self::Algorithm::*;

        match self {
            A128KW | A192KW | A256KW | AES_GCM_KW(_) | PBES2(_) => {
                AlgorithmType::SymmetricKeyWrapping
            }
            RSA1_5 | RSA_OAEP | RSA_OAEP_256 => AlgorithmType::AsymmetricKeyEncryption,
            DirectSymmetricKey => AlgorithmType::DirectEncryption,
            ECDH_ES => AlgorithmType::DirectKeyAgreement,
            ECDH_ES_A128KW | ECDH_ES_A192KW | ECDH_ES_A256KW => {
                AlgorithmType::KeyAgreementWithKeyWrapping
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
        use self::Algorithm::{DirectSymmetricKey, AES_GCM_KW};

        match self {
            DirectSymmetricKey => Self::cek_direct(key),
            AES_GCM_KW(_) => Self::cek_aes_gcm(content_alg),
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
                algorithm: Some(super::Algorithm::ContentEncryption(content_alg)),
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
        use self::Algorithm::{DirectSymmetricKey, AES_GCM_KW, PBES2};

        match self {
            AES_GCM_KW(kma) => {
                let nonce = header.nonce.as_deref().ok_or(Error::UnsupportedOperation)?;
                let encrypted = kma.aes_gcm_encrypt(payload, key.algorithm.octet_key()?, nonce)?;
                header.tag = Some(encrypted.tag);
                Ok(encrypted.encrypted)
            }
            PBES2(kma) => kma.encrypt(
                payload,
                key.algorithm.octet_key()?,
                header.salt.as_deref().ok_or(Error::UnsupportedOperation)?,
                header.count.unwrap_or_default(),
            ),
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
        use self::Algorithm::{DirectSymmetricKey, AES_GCM_KW, PBES2};

        match self {
            AES_GCM_KW(kma) => kma.aes_gcm_decrypt(
                &EncryptionResult {
                    encrypted: encrypted.to_vec(),
                    nonce: header.nonce.take().unwrap_or_default(),
                    tag: header.tag.take().unwrap_or_default(),
                    ..Default::default()
                },
                key.algorithm.octet_key()?,
            ),
            PBES2(kma) => kma.decrypt(
                encrypted,
                key.algorithm.octet_key()?,
                &header.salt.take().ok_or(Error::UnsupportedOperation)?,
                header.count.take().unwrap_or_default(),
            ),
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

        let cek_alg = Algorithm::DirectSymmetricKey;
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

        let cek_alg = Algorithm::AES_GCM_KW(AES_GCM::A128);
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

        let cek_alg = Algorithm::AES_GCM_KW(AES_GCM::A256);
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

mod serde_impl {
    use crate::jwa::kma::{AES_GCM, PBES2};

    use super::Algorithm;

    impl<'de> serde::Deserialize<'de> for Algorithm {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct Field(Algorithm);
            struct FieldVisitor;

            impl<'de> serde::de::Visitor<'de> for FieldVisitor {
                type Value = Field;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("variant identifier")
                }

                fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    self.visit_bytes(value.as_bytes())
                }

                fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let value = match value {
                        b"RSA1_5" => Algorithm::RSA1_5,
                        b"RSA-OAEP" => Algorithm::RSA_OAEP,
                        b"RSA-OAEP-256" => Algorithm::RSA_OAEP_256,
                        b"A128KW" => Algorithm::A128KW,
                        b"A192KW" => Algorithm::A192KW,
                        b"A256KW" => Algorithm::A256KW,
                        b"dir" => Algorithm::DirectSymmetricKey,
                        b"ECDH-ES" => Algorithm::ECDH_ES,
                        b"ECDH-ES+A128KW" => Algorithm::ECDH_ES_A128KW,
                        b"ECDH-ES+A192KW" => Algorithm::ECDH_ES_A192KW,
                        b"ECDH-ES+A256KW" => Algorithm::ECDH_ES_A256KW,
                        b"A128GCMKW" => Algorithm::AES_GCM_KW(AES_GCM::A128),
                        b"A192GCMKW" => Algorithm::AES_GCM_KW(AES_GCM::A192),
                        b"A256GCMKW" => Algorithm::AES_GCM_KW(AES_GCM::A256),
                        b"PBES2-HS256+A128KW" => Algorithm::PBES2(PBES2::HS256_A128KW),
                        b"PBES2-HS384+A192KW" => Algorithm::PBES2(PBES2::HS384_A192KW),
                        b"PBES2-HS512+A256KW" => Algorithm::PBES2(PBES2::HS512_A256KW),
                        _ => {
                            let value = String::from_utf8_lossy(value);
                            return Err(serde::de::Error::unknown_variant(&value, VARIANTS));
                        }
                    };
                    Ok(Field(value))
                }
            }
            impl<'de> serde::Deserialize<'de> for Field {
                #[inline]
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    deserializer.deserialize_identifier(FieldVisitor)
                }
            }
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Algorithm;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("enum KeyManagementAlgorithm")
                }
                fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::EnumAccess<'de>,
                {
                    let (Field(kma), variant) = serde::de::EnumAccess::variant(data)?;
                    serde::de::VariantAccess::unit_variant(variant)?;
                    Ok(kma)
                }
            }
            static VARIANTS: &[&str] = &[
                "RSA1_5",
                "RSA-OAEP",
                "RSA-OAEP-256",
                "A128KW",
                "A192KW",
                "A256KW",
                "dir",
                "ECDH-ES",
                "ECDH-ES+A128KW",
                "ECDH-ES+A192KW",
                "ECDH-ES+A256KW",
                "A128GCMKW",
                "A192GCMKW",
                "A256GCMKW",
                "PBES2-HS256+A128KW",
                "PBES2-HS384+A192KW",
                "PBES2-HS512+A256KW",
            ];
            serde::Deserializer::deserialize_enum(
                deserializer,
                "KeyManagementAlgorithm",
                VARIANTS,
                Visitor,
            )
        }
    }

    impl serde::Serialize for Algorithm {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let (idx, name) = match *self {
                Algorithm::RSA1_5 => (0u32, "RSA1_5"),
                Algorithm::RSA_OAEP => (1u32, "RSA-OAEP"),
                Algorithm::RSA_OAEP_256 => (2u32, "RSA-OAEP-256"),
                Algorithm::A128KW => (3u32, "A128KW"),
                Algorithm::A192KW => (4u32, "A192KW"),
                Algorithm::A256KW => (5u32, "A256KW"),
                Algorithm::DirectSymmetricKey => (6u32, "dir"),
                Algorithm::ECDH_ES => (7u32, "ECDH-ES"),
                Algorithm::ECDH_ES_A128KW => (8u32, "ECDH-ES+A128KW"),
                Algorithm::ECDH_ES_A192KW => (9u32, "ECDH-ES+A192KW"),
                Algorithm::ECDH_ES_A256KW => (10u32, "ECDH-ES+A256KW"),
                Algorithm::AES_GCM_KW(AES_GCM::A128) => (11u32, "A128GCMKW"),
                Algorithm::AES_GCM_KW(AES_GCM::A192) => (12u32, "A192GCMKW"),
                Algorithm::AES_GCM_KW(AES_GCM::A256) => (13u32, "A256GCMKW"),
                Algorithm::PBES2(PBES2::HS256_A128KW) => (14u32, "PBES2-HS256+A128KW"),
                Algorithm::PBES2(PBES2::HS384_A192KW) => (15u32, "PBES2-HS384+A192KW"),
                Algorithm::PBES2(PBES2::HS512_A256KW) => (16u32, "PBES2-HS512+A256KW"),
            };
            serializer.serialize_unit_variant("KeyManagementAlgorithm", idx, name)
        }
    }
}
