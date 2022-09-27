//! [JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518)
//!
//! Typically, you will not use these directly, but as part of a JWS or JWE.

use std::fmt;

use once_cell::sync::Lazy;
use ring::constant_time::verify_slices_are_equal;
use ring::rand::SystemRandom;
use ring::signature::KeyPair;
use ring::{aead, hmac, rand, signature};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::errors::Error;
use crate::jwa::kma::aes_gcm::{aes_gcm_decrypt, aes_gcm_encrypt};
use crate::jwk;
use crate::jws::Secret;

use ring::rand::SecureRandom;

pub mod kma;
mod cea {
    pub mod aes_cbc_hmac_sha;
}

/// AES GCM Nonce length, in bytes
const AES_GCM_NONCE_LENGTH: usize = 96 / 8;
/// AES CBC HMAC SHA Nonce length, in bytes
const AES_CBC_HMAC_SHA_NONCE_LENGTH: usize = 128 / 8;

/// A zeroed AES GCM Nonce EncryptionOptions
static AES_GCM_ZEROED_NONCE: Lazy<EncryptionOptions> = Lazy::new(|| EncryptionOptions::AES_GCM {
    nonce: vec![0; AES_GCM_NONCE_LENGTH],
});
/// A zeroed AES GCM Nonce EncryptionOptions
static AES_CBC_HMAC_SHA_ZEROED_NONCE: Lazy<EncryptionOptions> =
    Lazy::new(|| EncryptionOptions::AES_CBC_HMAC_SHA {
        nonce: vec![0; AES_CBC_HMAC_SHA_NONCE_LENGTH],
    });

/// Options to be passed in while performing an encryption operation, if required by the algorithm.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum EncryptionOptions {
    /// No options are required. Most algorithms do not require additional parameters
    None,
    /// Options for AES GCM encryption.
    AES_GCM {
        /// Initialization vector, or nonce for the AES GCM encryption. _MUST BE_ 96 bits long.
        ///
        /// AES GCM encryption operations should not reuse the nonce, or initialization vector.
        /// Users should keep track of previously used
        /// nonces and not reuse them. A simple way to keep track is to simply increment the nonce
        /// as a 96 bit counter.
        nonce: Vec<u8>,
    },
    /// Options for AES CBC HMAC SHA encryption.
    AES_CBC_HMAC_SHA {
        /// Initialization vector, or nonce for the AES CBC HMAC SHA encryption. _MUST BE_ 128 bits long.
        ///
        /// AES CBC HMAC SHA encryption operations should not reuse the nonce, or initialization vector.
        /// Users should keep track of previously used
        /// nonces and not reuse them. A simple way to keep track is to simply increment the nonce
        /// as a 128 bit counter.
        nonce: Vec<u8>,
    },
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
/// Algorithms described by [RFC 7518](https://tools.ietf.org/html/rfc7518).
/// This enum is serialized `untagged`.
#[serde(untagged)]
pub enum Algorithm {
    /// Algorithms meant for Digital signature or MACs
    /// See [RFC7518#3](https://tools.ietf.org/html/rfc7518#section-3)
    Signature(SignatureAlgorithm),
    /// Algorithms meant for key management. The algorithms are either meant to
    /// encrypt a content encryption key or determine the content encryption key.
    /// See [RFC7518#4](https://tools.ietf.org/html/rfc7518#section-4)
    KeyManagement(kma::Algorithm),
    /// Algorithms meant for content encryption.
    /// See [RFC7518#5](https://tools.ietf.org/html/rfc7518#section-5)
    ContentEncryption(ContentEncryptionAlgorithm),
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
/// The algorithms supported for digital signature and MACs, defined by
/// [RFC7518#3](https://tools.ietf.org/html/rfc7518#section-3).
pub enum SignatureAlgorithm {
    /// No encryption/signature is included for the JWT.
    /// During verification, the signature _MUST BE_ empty or verification  will fail.
    #[serde(rename = "none")]
    None,
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
    /// ECDSA using P-256 and SHA-256
    ES256,
    /// ECDSA using P-384 and SHA-384
    ES384,
    /// ECDSA using P-521 and SHA-512 --
    /// This variant is [unsupported](https://github.com/briansmith/ring/issues/268) and will probably never be.
    ES512,
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    /// The size of the salt value is the same size as the hash function output.
    PS256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    /// The size of the salt value is the same size as the hash function output.
    PS384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    /// The size of the salt value is the same size as the hash function output.
    PS512,
}

/// Algorithms meant for content encryption.
/// See [RFC7518#5](https://tools.ietf.org/html/rfc7518#section-5)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum ContentEncryptionAlgorithm {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm enc
    #[serde(rename = "A128CBC-HS256")]
    A128CBC_HS256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm enc
    #[serde(rename = "A192CBC-HS384")]
    A192CBC_HS384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm enc
    #[serde(rename = "A256CBC-HS512")]
    A256CBC_HS512,
    /// AES GCM using 128-bit key
    A128GCM,
    /// AES GCM using 192-bit key
    /// This is [not supported](https://github.com/briansmith/ring/issues/112) by `ring`.
    A192GCM,
    /// AES GCM using 256-bit key
    A256GCM,
}

/// The result returned from an encryption operation
// TODO: Might have to turn this into an enum
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct EncryptionResult {
    /// The initialization vector, or nonce used in the encryption
    pub nonce: Vec<u8>,
    /// The encrypted payload
    pub encrypted: Vec<u8>,
    /// The authentication tag
    pub tag: Vec<u8>,
    /// Additional authenticated data that is integrity protected but not encrypted
    pub additional_data: Vec<u8>,
}

impl Default for EncryptionOptions {
    fn default() -> Self {
        EncryptionOptions::None
    }
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        SignatureAlgorithm::HS256
    }
}

impl Default for ContentEncryptionAlgorithm {
    fn default() -> Self {
        ContentEncryptionAlgorithm::A128GCM
    }
}

impl EncryptionOptions {
    /// Description of the type of key
    pub fn description(&self) -> &'static str {
        match self {
            EncryptionOptions::None => "None",
            EncryptionOptions::AES_GCM { .. } => "AES GCM Nonce/Initialization Vector",
            EncryptionOptions::AES_CBC_HMAC_SHA { .. } => {
                "AES CBC HMAC SHA Nonce/Initialization Vector"
            }
        }
    }
}

impl fmt::Display for EncryptionOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl SignatureAlgorithm {
    /// Take some bytes and sign it according to the algorithm and secret provided.
    pub fn sign(self, data: &[u8], secret: &Secret) -> Result<Vec<u8>, Error> {
        use self::SignatureAlgorithm::*;

        match self {
            None => Self::sign_none(secret),
            HS256 | HS384 | HS512 => Self::sign_hmac(data, secret, self),
            RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => Self::sign_rsa(data, secret, self),
            ES256 | ES384 | ES512 => Self::sign_ecdsa(data, secret, self),
        }
    }

    /// Verify signature based on the algorithm and secret provided.
    pub fn verify(
        self,
        expected_signature: &[u8],
        data: &[u8],
        secret: &Secret,
    ) -> Result<(), Error> {
        use self::SignatureAlgorithm::*;

        match self {
            None => Self::verify_none(expected_signature, secret),
            HS256 | HS384 | HS512 => Self::verify_hmac(expected_signature, data, secret, self),
            RS256 | RS384 | RS512 | PS256 | PS384 | PS512 | ES256 | ES384 | ES512 => {
                Self::verify_public_key(expected_signature, data, secret, self)
            }
        }
    }

    /// Returns the type of operations the key is meant for
    fn sign_none(secret: &Secret) -> Result<Vec<u8>, Error> {
        match *secret {
            Secret::None => {}
            _ => Err("Invalid secret type. `None` should be provided".to_string())?,
        };
        Ok(vec![])
    }

    fn sign_hmac(
        data: &[u8],
        secret: &Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        let secret = match *secret {
            Secret::Bytes(ref secret) => secret,
            _ => Err("Invalid secret type. A byte array is required".to_string())?,
        };

        let algorithm = match algorithm {
            SignatureAlgorithm::HS256 => &hmac::HMAC_SHA256,
            SignatureAlgorithm::HS384 => &hmac::HMAC_SHA384,
            SignatureAlgorithm::HS512 => &hmac::HMAC_SHA512,
            _ => unreachable!("Should not happen"),
        };
        let key = hmac::Key::new(*algorithm, secret);
        Ok(hmac::sign(&key, data).as_ref().to_vec())
    }

    fn sign_rsa(
        data: &[u8],
        secret: &Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        let key_pair = match *secret {
            Secret::RsaKeyPair(ref key_pair) => key_pair,
            _ => Err("Invalid secret type. A RsaKeyPair is required".to_string())?,
        };

        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; key_pair.public_modulus_len()];
        let padding_algorithm: &dyn signature::RsaEncoding = match algorithm {
            SignatureAlgorithm::RS256 => &signature::RSA_PKCS1_SHA256,
            SignatureAlgorithm::RS384 => &signature::RSA_PKCS1_SHA384,
            SignatureAlgorithm::RS512 => &signature::RSA_PKCS1_SHA512,
            SignatureAlgorithm::PS256 => &signature::RSA_PSS_SHA256,
            SignatureAlgorithm::PS384 => &signature::RSA_PSS_SHA384,
            SignatureAlgorithm::PS512 => &signature::RSA_PSS_SHA512,
            _ => unreachable!("Should not happen"),
        };

        key_pair.sign(padding_algorithm, &rng, data, &mut signature)?;
        Ok(signature)
    }

    fn sign_ecdsa(
        data: &[u8],
        secret: &Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        let key_pair = match *secret {
            Secret::EcdsaKeyPair(ref key_pair) => key_pair,
            _ => Err("Invalid secret type. An EcdsaKeyPair is required".to_string())?,
        };
        if let SignatureAlgorithm::ES512 = algorithm {
            // See https://github.com/briansmith/ring/issues/268
            Err(Error::UnsupportedOperation)
        } else {
            let rng = rand::SystemRandom::new();
            let sig = key_pair.as_ref().sign(&rng, data)?;
            Ok(sig.as_ref().to_vec())
        }
    }

    fn verify_none(expected_signature: &[u8], secret: &Secret) -> Result<(), Error> {
        match *secret {
            Secret::None => {}
            _ => Err("Invalid secret type. `None` should be provided".to_string())?,
        };

        if expected_signature.is_empty() {
            Ok(())
        } else {
            Err(Error::UnspecifiedCryptographicError)
        }
    }

    fn verify_hmac(
        expected_signature: &[u8],
        data: &[u8],
        secret: &Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<(), Error> {
        let actual_signature = Self::sign_hmac(data, secret, algorithm)?;
        verify_slices_are_equal(expected_signature, actual_signature.as_ref())?;
        Ok(())
    }

    fn verify_public_key(
        expected_signature: &[u8],
        data: &[u8],
        secret: &Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<(), Error> {
        match *secret {
            Secret::PublicKey(ref public_key) => {
                let verification_algorithm: &dyn signature::VerificationAlgorithm = match algorithm
                {
                    SignatureAlgorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    SignatureAlgorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    SignatureAlgorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    SignatureAlgorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
                    SignatureAlgorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
                    SignatureAlgorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
                    SignatureAlgorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED,
                    SignatureAlgorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED,
                    SignatureAlgorithm::ES512 => Err(Error::UnsupportedOperation)?,
                    _ => unreachable!("Should not happen"),
                };

                let public_key = signature::UnparsedPublicKey::new(
                    verification_algorithm,
                    public_key.as_slice(),
                );
                public_key.verify(data, expected_signature)?;
                Ok(())
            }
            Secret::RsaKeyPair(ref keypair) => {
                let verification_algorithm: &dyn signature::VerificationAlgorithm = match algorithm
                {
                    SignatureAlgorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    SignatureAlgorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    SignatureAlgorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    SignatureAlgorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
                    SignatureAlgorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
                    SignatureAlgorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
                    _ => unreachable!("Should not happen"),
                };

                let public_key =
                    signature::UnparsedPublicKey::new(verification_algorithm, keypair.public_key());
                public_key.verify(data, expected_signature)?;
                Ok(())
            }
            Secret::RSAModulusExponent { ref n, ref e } => {
                let params = match algorithm {
                    SignatureAlgorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    SignatureAlgorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    SignatureAlgorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    SignatureAlgorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
                    SignatureAlgorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
                    SignatureAlgorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
                    _ => unreachable!("(n,e) secret with a non-rsa algorithm should not happen"),
                };

                let n_big_endian = n.to_bytes_be();
                let e_big_endian = e.to_bytes_be();
                let public_key = signature::RsaPublicKeyComponents {
                    n: n_big_endian,
                    e: e_big_endian,
                };
                public_key.verify(params, data, expected_signature)?;
                Ok(())
            }
            Secret::EcdsaKeyPair(ref keypair) => {
                let verification_algorithm: &dyn signature::VerificationAlgorithm = match algorithm
                {
                    SignatureAlgorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED,
                    SignatureAlgorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED,
                    SignatureAlgorithm::ES512 => Err(Error::UnsupportedOperation)?,
                    _ => unreachable!("Should not happen"),
                };

                let public_key =
                    signature::UnparsedPublicKey::new(verification_algorithm, keypair.public_key());
                public_key.verify(data, expected_signature)?;
                Ok(())
            }
            _ => unreachable!("This is a private method and should not be called erroneously."),
        }
    }
}

impl ContentEncryptionAlgorithm {
    /// Convenience function to generate a new random key with the required length
    pub fn generate_key(self) -> Result<Vec<u8>, Error> {
        use self::ContentEncryptionAlgorithm::{A128GCM, A256GCM};

        let length: usize = match self {
            A128GCM => 128 / 8,
            A256GCM => 256 / 8,
            _ => Err(Error::UnsupportedOperation)?,
        };

        let mut key: Vec<u8> = vec![0; length];
        SystemRandom::new().fill(&mut key)?;
        Ok(key)
    }

    /// Encrypt some payload with the provided algorith
    pub fn encrypt<T: Serialize + DeserializeOwned>(
        self,
        payload: &[u8],
        aad: &[u8],
        key: &jwk::JWK<T>,
        options: &EncryptionOptions,
    ) -> Result<EncryptionResult, Error> {
        use self::ContentEncryptionAlgorithm::{
            A128CBC_HS256, A128GCM, A192CBC_HS384, A192GCM, A256CBC_HS512, A256GCM,
        };

        match self {
            A128GCM | A192GCM | A256GCM => {
                self.aes_gcm_encrypt(payload, aad, key.algorithm.octet_key()?, options)
            }
            A128CBC_HS256 | A192CBC_HS384 | A256CBC_HS512 => {
                self.aes_cbc_encrypt(payload, aad, key, options)
            }
        }
    }

    /// Decrypt some payload with the provided algorith,
    pub fn decrypt<T: Serialize + DeserializeOwned>(
        self,
        encrypted: &EncryptionResult,
        key: &jwk::JWK<T>,
    ) -> Result<Vec<u8>, Error> {
        use self::ContentEncryptionAlgorithm::{
            A128CBC_HS256, A128GCM, A192CBC_HS384, A192GCM, A256CBC_HS512, A256GCM,
        };

        match self {
            A128GCM | A192GCM | A256GCM => self.aes_gcm_decrypt(encrypted, key.octet_key()?),
            A128CBC_HS256 | A192CBC_HS384 | A256CBC_HS512 => self.aes_cbc_decrypt(encrypted, key),
        }
    }

    /// Generate a new random `EncryptionOptions` based on the algorithm
    pub(crate) fn random_encryption_options(self) -> Result<EncryptionOptions, Error> {
        use self::ContentEncryptionAlgorithm::{
            A128CBC_HS256, A128GCM, A192CBC_HS384, A192GCM, A256CBC_HS512, A256GCM,
        };
        match self {
            A128GCM | A192GCM | A256GCM => Ok(EncryptionOptions::AES_GCM {
                nonce: random_aes_gcm_nonce()?,
            }),
            A128CBC_HS256 | A192CBC_HS384 | A256CBC_HS512 => {
                Ok(EncryptionOptions::AES_CBC_HMAC_SHA {
                    nonce: random_aes_cbc_nonce()?,
                })
            }
        }
    }

    fn aes_gcm_encrypt(
        self,
        payload: &[u8],
        aad: &[u8],
        key: &[u8],
        options: &EncryptionOptions,
    ) -> Result<EncryptionResult, Error> {
        use self::ContentEncryptionAlgorithm::{A128GCM, A256GCM};

        let algorithm = match self {
            A128GCM => &aead::AES_128_GCM,
            A256GCM => &aead::AES_256_GCM,
            _ => Err(Error::UnsupportedOperation)?,
        };

        let nonce = match *options {
            EncryptionOptions::AES_GCM { ref nonce } => Ok(nonce),
            ref others => Err(unexpected_encryption_options_error!(
                AES_GCM_ZEROED_NONCE,
                others
            )),
        }?;
        // FIXME: Should we check the nonce length here or leave it to ring?

        aes_gcm_encrypt(algorithm, payload, nonce.as_slice(), aad, key)
    }

    fn aes_gcm_decrypt(self, encrypted: &EncryptionResult, key: &[u8]) -> Result<Vec<u8>, Error> {
        use self::ContentEncryptionAlgorithm::{A128GCM, A256GCM};

        let algorithm = match self {
            A128GCM => &aead::AES_128_GCM,
            A256GCM => &aead::AES_256_GCM,
            _ => Err(Error::UnsupportedOperation)?,
        };
        aes_gcm_decrypt(algorithm, encrypted, key)
    }
}

pub(crate) fn random_aes_gcm_nonce() -> Result<Vec<u8>, Error> {
    let mut nonce: Vec<u8> = vec![0; AES_GCM_NONCE_LENGTH];
    SystemRandom::new().fill(&mut nonce)?;
    Ok(nonce)
}
pub(crate) fn random_aes_cbc_nonce() -> Result<Vec<u8>, Error> {
    let mut nonce: Vec<u8> = vec![0; AES_CBC_HMAC_SHA_NONCE_LENGTH];
    SystemRandom::new().fill(&mut nonce)?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use ring::constant_time::verify_slices_are_equal;

    use super::*;
    use crate::{jwa, Empty};

    #[test]
    fn sign_and_verify_none() {
        let expected_signature: Vec<u8> = vec![];
        let actual_signature = not_err!(
            SignatureAlgorithm::None.sign("payload".to_string().as_bytes(), &Secret::None,)
        );
        assert_eq!(expected_signature, actual_signature);

        not_err!(SignatureAlgorithm::None.verify(
            vec![].as_slice(),
            "payload".to_string().as_bytes(),
            &Secret::None
        ));
    }

    #[test]
    fn sign_and_verify_hs256() {
        let expected_base64 = "uC_LeRrOxXhZuYm0MKgmSIzi5Hn9-SMmvQoug3WkK6Q";
        let expected_bytes: Vec<u8> = not_err!(base64::decode_config(
            &expected_base64,
            base64::URL_SAFE_NO_PAD
        ));

        let actual_signature = not_err!(SignatureAlgorithm::HS256.sign(
            "payload".to_string().as_bytes(),
            &Secret::bytes_from_str("secret"),
        ));
        assert_eq!(
            &*base64::encode_config(actual_signature, base64::URL_SAFE_NO_PAD),
            expected_base64
        );

        not_err!(SignatureAlgorithm::HS256.verify(
            expected_bytes.as_slice(),
            "payload".to_string().as_bytes(),
            &Secret::bytes_from_str("secret"),
        ));
    }

    /// To generate the signature, use
    ///
    /// ```sh
    /// echo -n "payload" | openssl dgst -sha256 -sign test/fixtures/rsa_private_key.pem | base64
    /// ```
    ///
    /// The base64 encoding from this command will be in `STANDARD` form and not URL_SAFE.
    #[test]
    fn sign_and_verify_rs256() {
        let private_key =
            Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();
        // This is standard base64
        let expected_signature =
            "JIHqiBfUknrFPDLT0gxyoufD06S43ZqWN_PzQqHZqQ-met7kZmkSTYB_rUyotLMxlKkuXdnvKmWm\
             dwGAHWEwDvb5392pCmAAtmUIl6LormxJptWYb2PoF5jmtX_lwV8y4RYIh54Ai51162VARQCKAsxL\
             uH772MEChkcpjd31NWzaePWoi_IIk11iqy6uFWmbLLwzD_Vbpl2C6aHR3vQjkXZi05gA3zksjYAh\
             j-m7GgBt0UFOE56A4USjhQwpb4g3NEamgp51_kZ2ULi4Aoo_KJC6ynIm_pR6rEzBgwZjlCUnE-6o\
             5RPQZ8Oau03UDVH2EwZe-Q91LaWRvkKjGg5Tcw";
        let expected_signature_bytes: Vec<u8> = not_err!(base64::decode_config(
            &expected_signature,
            base64::URL_SAFE_NO_PAD
        ));

        let actual_signature =
            not_err!(SignatureAlgorithm::RS256.sign(payload_bytes, &private_key));
        assert_eq!(
            base64::encode_config(&actual_signature, base64::URL_SAFE_NO_PAD),
            expected_signature
        );

        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        not_err!(SignatureAlgorithm::RS256.verify(
            expected_signature_bytes.as_slice(),
            payload_bytes,
            &public_key,
        ));
    }

    #[test]
    fn sign_and_verify_rs256_key_params() {
        use num_bigint::BigUint;
        // There is no way in Ring right now to get these values from the key
        let params = Secret::RSAModulusExponent {
            n: BigUint::parse_bytes(
                b"D57336432EDB91A0A98E3BC2959C08D79017CBDF7AEA6EDCDEC611DA746E1\
                                      DBD144FB4391163E797FB392C438CC70AEA89796D8FCFF69646655AD02E00\
                                      169B5F1C4C9150D3399D80DCE6D8F6F057B105F5FC5EE774B0A8FF20A67D8\
                                      0E6707D380462D2CDCB913E6EE9EA7585CD504AE45B6930BC713D02999E36\
                                      BF449CFFA2385374F3850819056207880A2E8BA47EE8A86CBE4C361D6D54B\
                                      95F2E1668262F79C2774D4234B8D5C6D15A0E95493E308AA98F002A78BB92\
                                      8CB78F1E7E06243AB6D7EAFAB59F6446774B0479F6593F88F763978F14EFB\
                                      7F422B4C66E8EB53FF5E6DC4D3C92952D8413E06E2D9EB1DF50D8224FF3BD\
                                      319FF5E4258D06C578B9527B",
                16,
            )
            .unwrap(),
            e: BigUint::from(65537u32),
        };
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();
        let expected_signature =
            "JIHqiBfUknrFPDLT0gxyoufD06S43ZqWN_PzQqHZqQ-met7kZmkSTYB_rUyotLMxlKkuXdnvKmWm\
             dwGAHWEwDvb5392pCmAAtmUIl6LormxJptWYb2PoF5jmtX_lwV8y4RYIh54Ai51162VARQCKAsxL\
             uH772MEChkcpjd31NWzaePWoi_IIk11iqy6uFWmbLLwzD_Vbpl2C6aHR3vQjkXZi05gA3zksjYAh\
             j-m7GgBt0UFOE56A4USjhQwpb4g3NEamgp51_kZ2ULi4Aoo_KJC6ynIm_pR6rEzBgwZjlCUnE-6o\
             5RPQZ8Oau03UDVH2EwZe-Q91LaWRvkKjGg5Tcw";
        let expected_signature_bytes: Vec<u8> = not_err!(base64::decode_config(
            expected_signature,
            base64::URL_SAFE_NO_PAD
        ));

        not_err!(SignatureAlgorithm::RS256.verify(
            expected_signature_bytes.as_slice(),
            payload_bytes,
            &params,
        ));
    }

    /// This signature is non-deterministic.
    #[test]
    fn sign_and_verify_ps256_round_trip() {
        let private_key =
            Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();

        let actual_signature =
            not_err!(SignatureAlgorithm::PS256.sign(payload_bytes, &private_key));

        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        not_err!(SignatureAlgorithm::PS256.verify(
            actual_signature.as_slice(),
            payload_bytes,
            &public_key,
        ));
    }

    /// This signature is non-deterministic.
    #[test]
    fn sign_and_verify_ps256_round_trip_with_keypair() {
        let key = Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();

        let actual_signature = not_err!(SignatureAlgorithm::PS256.sign(payload_bytes, &key));

        not_err!(SignatureAlgorithm::PS256.verify(
            actual_signature.as_slice(),
            payload_bytes,
            &key,
        ));
    }

    /// To generate a (non-deterministic) signature:
    ///
    /// ```sh
    /// echo -n "payload" | openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
    ///    -sign test/fixtures/rsa_private_key.pem | base64
    /// ```
    ///
    /// The base64 encoding from this command will be in `STANDARD` form and not URL_SAFE.
    #[test]
    fn verify_ps256() {
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();
        let signature =
            "TiMXtt3Wmv/a/tbLWuJPDlFYMfuKsD7U5lbBUn2mBu8DLMLj1EplEZNmkB8w65BgUijnu9hxmhwv\
             ET2k7RrsYamEst6BHZf20hIK1yE/YWaktbVmAZwUDdIpXYaZn8ukTsMT06CDrVk6RXF0EPMaSL33\
             tFNPZpz4/3pYQdxco/n6DpaR5206wsur/8H0FwoyiFKanhqLb1SgZqyc+SXRPepjKc28wzBnfWl4\
             mmlZcJ2xk8O2/t1Y1/m/4G7drBwOItNl7EadbMVCetYnc9EILv39hjcL9JvaA9q0M2RB75DIu8SF\
             9Kr/l+wzUJjWAHthgqSBpe15jLkpO8tvqR89fw==";
        let signature_bytes: Vec<u8> = not_err!(base64::decode(signature.as_bytes()));
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        not_err!(SignatureAlgorithm::PS256.verify(
            signature_bytes.as_slice(),
            payload_bytes,
            &public_key,
        ));
    }

    /// This signature is non-deterministic.
    #[test]
    fn sign_and_verify_es256_round_trip() {
        let private_key = Secret::ecdsa_keypair_from_file(
            SignatureAlgorithm::ES256,
            "test/fixtures/ecdsa_private_key.p8",
        )
        .unwrap();
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();

        let actual_signature =
            not_err!(SignatureAlgorithm::ES256.sign(payload_bytes, &private_key));

        let public_key =
            Secret::public_key_from_file("test/fixtures/ecdsa_public_key.der").unwrap();
        not_err!(SignatureAlgorithm::ES256.verify(
            actual_signature.as_slice(),
            payload_bytes,
            &public_key,
        ));
    }

    /// This signature is non-deterministic.
    #[test]
    fn sign_and_verify_es256_round_trip_with_keypair() {
        let key = Secret::ecdsa_keypair_from_file(
            SignatureAlgorithm::ES256,
            "test/fixtures/ecdsa_private_key.p8",
        )
        .unwrap();
        let payload = "payload".to_string();
        let payload_bytes = payload.as_bytes();

        let actual_signature = not_err!(SignatureAlgorithm::ES256.sign(payload_bytes, &key));

        not_err!(SignatureAlgorithm::ES256.verify(
            actual_signature.as_slice(),
            payload_bytes,
            &key,
        ));
    }

    /// Test case from https://github.com/briansmith/ring/blob/a13b8e2/src/ec/suite_b/ecdsa_verify_fixed_tests.txt
    #[test]
    fn verify_es256() {
        let payload_bytes = Vec::<u8>::new();
        let public_key = "0430345FD47EA21A11129BE651B0884BFAC698377611ACC9F689458E13B9ED7D4B9D7599\
                          A68DCF125E7F31055CCB374CD04F6D6FD2B217438A63F6F667D50EF2F0";
        let public_key = Secret::PublicKey(hex::decode(public_key.as_bytes()).unwrap());
        let signature = "341F6779B75E98BB42E01095DD48356CBF9002DC704AC8BD2A8240B88D3796C6555843B1B\
                         4E264FE6FFE6E2B705A376C05C09404303FFE5D2711F3E3B3A010A1";
        let signature_bytes: Vec<u8> = hex::decode(signature.as_bytes()).unwrap();
        not_err!(SignatureAlgorithm::ES256.verify(
            signature_bytes.as_slice(),
            &payload_bytes,
            &public_key,
        ));
    }

    /// Test case from https://github.com/briansmith/ring/blob/a13b8e2/src/ec/suite_b/ecdsa_verify_fixed_tests.txt
    #[test]
    fn verify_es384() {
        let payload_bytes = Vec::<u8>::new();
        let public_key = "045C5E788A805C77D34128B8401CB59B2373B8B468336C9318252BF39FD31D2507557987\
                          A5180A9435F9FB8EB971C426F1C485170DCB18FB688A257F89387A09FC4C5B8BD4B320616\
                          B54A0A7B1D1D7C6A0C59F6DFF78C78AD4E3D6FCA9C9A17B96";
        let public_key = Secret::PublicKey(hex::decode(public_key.as_bytes()).unwrap());
        let signature = "85AC708D4B0126BAC1F5EEEBDF911409070A286FDDE5649582611B60046DE353761660DD0\
                         3903F58B44148F25142EEF8183475EC1F1392F3D6838ABC0C01724709C446888BED7F2CE4\
                         642C6839DC18044A2A6AB9DDC960BFAC79F6988E62D452";
        let signature_bytes: Vec<u8> = hex::decode(signature.as_bytes()).unwrap();
        not_err!(SignatureAlgorithm::ES384.verify(
            signature_bytes.as_slice(),
            &payload_bytes,
            &public_key,
        ));
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperation")]
    fn verify_es512() {
        let payload: Vec<u8> = vec![];
        let signature: Vec<u8> = vec![];
        let public_key = Secret::PublicKey(vec![]);
        SignatureAlgorithm::ES512
            .verify(signature.as_slice(), payload.as_slice(), &public_key)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_none() {
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        SignatureAlgorithm::None
            .verify(
                signature_bytes,
                "payload".to_string().as_bytes(),
                &Secret::None,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_hs256() {
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        SignatureAlgorithm::HS256
            .verify(
                signature_bytes,
                "payload".to_string().as_bytes(),
                &Secret::Bytes("secret".to_string().into_bytes()),
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_rs256() {
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        SignatureAlgorithm::RS256
            .verify(
                signature_bytes,
                "payload".to_string().as_bytes(),
                &public_key,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_ps256() {
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        SignatureAlgorithm::PS256
            .verify(
                signature_bytes,
                "payload".to_string().as_bytes(),
                &public_key,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_es256() {
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let invalid_signature = "broken".to_string();
        let signature_bytes = invalid_signature.as_bytes();
        SignatureAlgorithm::ES256
            .verify(
                signature_bytes,
                "payload".to_string().as_bytes(),
                &public_key,
            )
            .unwrap();
    }

    #[test]
    fn rng_is_created() {
        let rng = SystemRandom::new();
        let mut random: Vec<u8> = vec![0; 8];
        rng.fill(&mut random).unwrap();
    }

    /// `ContentEncryptionAlgorithm::A128GCM` generates CEK of the right length
    #[test]
    fn aes128gcm_key_length() {
        let enc_alg = jwa::ContentEncryptionAlgorithm::A128GCM;
        let cek = not_err!(enc_alg.generate_key());
        assert_eq!(cek.len(), 128 / 8);
    }

    /// `ContentEncryptionAlgorithm::A256GCM` generates CEK of the right length
    #[test]
    fn aes256gcm_key_length() {
        let enc_alg = jwa::ContentEncryptionAlgorithm::A256GCM;
        let cek = not_err!(enc_alg.generate_key());
        assert_eq!(cek.len(), 256 / 8);
    }

    #[test]
    fn aes128gcm_encryption_round_trip() {
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

        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };

        let payload = "狼よ、我が敵を食らえ！";
        let aad = "My servants never die!";
        let enc_alg = jwa::ContentEncryptionAlgorithm::A128GCM;
        let encrypted_payload =
            not_err!(enc_alg.encrypt(payload.as_bytes(), aad.as_bytes(), &key, &options,));

        let decrypted_payload = not_err!(enc_alg.decrypt(&encrypted_payload, &key));
        assert!(verify_slices_are_equal(payload.as_bytes(), &decrypted_payload).is_ok());
    }

    #[test]
    fn aes1256gcm_encryption_round_trip() {
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

        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };

        let payload = "狼よ、我が敵を食らえ！";
        let aad = "My servants never die!";
        let enc_alg = jwa::ContentEncryptionAlgorithm::A256GCM;
        let encrypted_payload =
            not_err!(enc_alg.encrypt(payload.as_bytes(), aad.as_bytes(), &key, &options,));

        let decrypted_payload = not_err!(enc_alg.decrypt(&encrypted_payload, &key));
        assert!(verify_slices_are_equal(payload.as_bytes(), &decrypted_payload).is_ok());
    }
}
