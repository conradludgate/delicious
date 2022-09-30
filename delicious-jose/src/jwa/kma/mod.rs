//! [Cryptographic Algorithms for Key Management](https://www.rfc-editor.org/rfc/rfc7518#section-4)

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{errors::Error, jwk::OctetKey};

pub(crate) mod aes_gcm;
mod pbes2_aes_kw;

pub use self::aes_gcm::{AesGcmKwHeader, A128GCMKW, A192GCMKW, A256GCMKW, AES_GCM};
pub use pbes2_aes_kw::{
    Pbes2, Pbes2Header, PBES2, PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW,
};

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
}

/// [Cryptographic Algorithms for Key Management](https://www.rfc-editor.org/rfc/rfc7518#section-4)
pub trait KMA {
    /// The name specified in the `alg` header.
    const ALG: Algorithm;

    /// Key used to derive the Cek
    type Key;
    /// Content Encryption Key
    type Cek;
    /// Values to store in the header, used to unwrap the Cek
    type Header: Serialize + DeserializeOwned;
    /// Settings used to wrap the key
    type WrapSettings;

    /// Generate a key for the CEA
    fn generate_key<CEA>(_key: &Self::Key) -> Self::Cek
    where
        CEA: super::cea::CEA<Cek = Self::Cek>,
    {
        CEA::generate_cek()
    }

    /// Wraps the content encryption key
    fn wrap(
        cek: &Self::Cek,
        key: &Self::Key,
        settings: Self::WrapSettings,
    ) -> Result<(Vec<u8>, Self::Header), Error>;

    /// unwraps the content encryption key
    fn unwrap(
        encrypted_cek: &[u8],
        key: &Self::Key,
        settings: Self::Header,
    ) -> Result<Self::Cek, Error>;
}

/// [Direct Encryption with a Shared Symmetric Key](https://datatracker.ietf.org/doc/html/rfc7518#section-4.5)
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DirectEncryption;

impl KMA for DirectEncryption {
    const ALG: Algorithm = Algorithm::DirectSymmetricKey;
    type Key = OctetKey;
    type Cek = OctetKey;
    type Header = ();
    type WrapSettings = ();

    fn generate_key<CEA>(key: &Self::Key) -> Self::Cek
    where
        CEA: super::cea::CEA<Cek = Self::Cek>,
    {
        key.clone()
    }

    fn wrap(
        _cek: &Self::Cek,
        _key: &Self::Key,
        _settings: Self::WrapSettings,
    ) -> Result<(Vec<u8>, Self::Header), Error> {
        Ok((vec![], ()))
    }

    fn unwrap(
        encrypted_cek: &[u8],
        key: &Self::Key,
        _settings: Self::Header,
    ) -> Result<Self::Cek, Error> {
        if encrypted_cek.is_empty() {
            Ok(key.clone())
        } else {
            Err(Error::DecodeError(crate::errors::DecodeError::InvalidToken))
        }
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

    impl Algorithm {
        pub fn as_str(&self) -> &'static str {
            match *self {
                Algorithm::RSA1_5 => "RSA1_5",
                Algorithm::RSA_OAEP => "RSA-OAEP",
                Algorithm::RSA_OAEP_256 => "RSA-OAEP-256",
                Algorithm::A128KW => "A128KW",
                Algorithm::A192KW => "A192KW",
                Algorithm::A256KW => "A256KW",
                Algorithm::DirectSymmetricKey => "dir",
                Algorithm::ECDH_ES => "ECDH-ES",
                Algorithm::ECDH_ES_A128KW => "ECDH-ES+A128KW",
                Algorithm::ECDH_ES_A192KW => "ECDH-ES+A192KW",
                Algorithm::ECDH_ES_A256KW => "ECDH-ES+A256KW",
                Algorithm::AES_GCM_KW(AES_GCM::A128) => "A128GCMKW",
                Algorithm::AES_GCM_KW(AES_GCM::A192) => "A192GCMKW",
                Algorithm::AES_GCM_KW(AES_GCM::A256) => "A256GCMKW",
                Algorithm::PBES2(PBES2::HS256_A128KW) => "PBES2-HS256+A128KW",
                Algorithm::PBES2(PBES2::HS384_A192KW) => "PBES2-HS384+A192KW",
                Algorithm::PBES2(PBES2::HS512_A256KW) => "PBES2-HS512+A256KW",
            }
        }
    }

    impl serde::Serialize for Algorithm {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let idx = match *self {
                Algorithm::RSA1_5 => 0u32,
                Algorithm::RSA_OAEP => 1u32,
                Algorithm::RSA_OAEP_256 => 2u32,
                Algorithm::A128KW => 3u32,
                Algorithm::A192KW => 4u32,
                Algorithm::A256KW => 5u32,
                Algorithm::DirectSymmetricKey => 6u32,
                Algorithm::ECDH_ES => 7u32,
                Algorithm::ECDH_ES_A128KW => 8u32,
                Algorithm::ECDH_ES_A192KW => 9u32,
                Algorithm::ECDH_ES_A256KW => 10u32,
                Algorithm::AES_GCM_KW(AES_GCM::A128) => 11u32,
                Algorithm::AES_GCM_KW(AES_GCM::A192) => 12u32,
                Algorithm::AES_GCM_KW(AES_GCM::A256) => 13u32,
                Algorithm::PBES2(PBES2::HS256_A128KW) => 14u32,
                Algorithm::PBES2(PBES2::HS384_A192KW) => 15u32,
                Algorithm::PBES2(PBES2::HS512_A256KW) => 16u32,
            };
            serializer.serialize_unit_variant("KeyManagementAlgorithm", idx, self.as_str())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{jwa::cea, test::random_vec};

    fn cek_oct_key(len: usize) -> OctetKey {
        OctetKey::new(random_vec(len))
    }

    /// `KeyManagementAlgorithm::DirectSymmetricKey` returns the same key when CEK is requested
    #[test]
    fn dir_cek_returns_provided_key() {
        let key = cek_oct_key(256 / 8);

        let cek = DirectEncryption::generate_key::<cea::A256GCM>(&key);

        assert_eq!(cek, key);
    }

    /// `KeyManagementAlgorithm::A128GCMKW` returns a random key with the right length when CEK is requested
    #[test]
    fn cek_aes128gcmkw_returns_right_key_length() {
        let key = cek_oct_key(128 / 8);

        let cek = A128GCMKW::generate_key::<cea::A128GCM>(&key);
        assert_eq!(cek.as_bytes().len(), 128 / 8);
        assert_ne!(cek, key);

        let cek = A128GCMKW::generate_key::<cea::A256GCM>(&key);
        assert_eq!(cek.as_bytes().len(), 256 / 8);
        assert_ne!(cek, key);
    }

    /// `KeyManagementAlgorithm::A256GCMKW` returns a random key with the right length when CEK is requested
    #[test]
    fn cek_aes256gcmkw_returns_right_key_length() {
        let key = cek_oct_key(256 / 8);

        let cek = A256GCMKW::generate_key::<cea::A128GCM>(&key);
        assert_eq!(cek.as_bytes().len(), 128 / 8);
        assert_ne!(cek, key);

        let cek = A256GCMKW::generate_key::<cea::A256GCM>(&key);
        assert_eq!(cek.as_bytes().len(), 256 / 8);
        assert_ne!(cek, key);
    }
}
