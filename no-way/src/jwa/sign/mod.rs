//! [Cryptographic Algorithms for Digital Signatures and MACs](https://www.rfc-editor.org/rfc/rfc7518#section-3)

use serde::{Deserialize, Serialize};

use crate::errors::Error;

mod ecdsa;
mod hmac_sha2;
pub use self::ecdsa::{Ecdsa, ES256, ES384};
pub use hmac_sha2::{HmacSha, HS256, HS384, HS512};

/// [Cryptographic Algorithms for Digital Signatures and MACs](https://www.rfc-editor.org/rfc/rfc7518#section-3)
pub trait Sign {
    /// The name specified in the `alg` header.
    const ALG: Algorithm;

    /// The key type that can be used to sign/verify the payload
    type Key;

    /// Sign a payload using the key, returns the signature.
    fn sign(key: &Self::Key, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Verifies the payload against the signature.
    /// Returns an error if the signature is invalid
    fn verify(key: &Self::Key, data: &[u8], signature: &[u8]) -> Result<(), Error>;
}

/// The none-signing algorithm. You probably don't want to use this in production
///
/// Your tokens will not be signed, and there will be no data integrity
pub struct None;

impl Sign for None {
    const ALG: Algorithm = Algorithm::None;
    type Key = ();
    fn sign(_key: &Self::Key, _data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(vec![])
    }
    fn verify(_key: &Self::Key, _data: &[u8], signature: &[u8]) -> Result<(), Error> {
        if signature.is_empty() {
            Ok(())
        } else {
            Err(Error::UnspecifiedCryptographicError)
        }
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
/// The algorithms supported for digital signature and MACs, defined by
/// [RFC7518#3](https://tools.ietf.org/html/rfc7518#section-3).
pub enum Algorithm {
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

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::HS256
    }
}

impl Algorithm {
    /// Turn this signature algorithm into it's
    /// well-known `alg` header name
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::None => "none",
            Algorithm::HS256 => "HS256",
            Algorithm::HS384 => "HS384",
            Algorithm::HS512 => "HS512",
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            Algorithm::ES512 => "ES512",
            Algorithm::PS256 => "PS256",
            Algorithm::PS384 => "PS384",
            Algorithm::PS512 => "PS512",
        }
    }

    // fn sign_rsa(data: &[u8], secret: &Secret, algorithm: Algorithm) -> Result<Vec<u8>, Error> {
    //     let key_pair = match *secret {
    //         Secret::RsaKeyPair(ref key_pair) => key_pair,
    //         _ => Err("Invalid secret type. A RsaKeyPair is required".to_string())?,
    //     };

    //     let rng = ring::rand::SystemRandom::new();
    //     let mut signature = vec![0; key_pair.public_modulus_len()];
    //     let padding_algorithm: &dyn signature::RsaEncoding = match algorithm {
    //         Algorithm::RS256 => &signature::RSA_PKCS1_SHA256,
    //         Algorithm::RS384 => &signature::RSA_PKCS1_SHA384,
    //         Algorithm::RS512 => &signature::RSA_PKCS1_SHA512,
    //         Algorithm::PS256 => &signature::RSA_PSS_SHA256,
    //         Algorithm::PS384 => &signature::RSA_PSS_SHA384,
    //         Algorithm::PS512 => &signature::RSA_PSS_SHA512,
    //         _ => unreachable!("Should not happen"),
    //     };

    //     key_pair.sign(padding_algorithm, &rng, data, &mut signature)?;
    //     Ok(signature)
    // }

    // fn verify_public_key(
    //     expected_signature: &[u8],
    //     data: &[u8],
    //     secret: &Secret,
    //     algorithm: Algorithm,
    // ) -> Result<(), Error> {
    //     match *secret {
    //         Secret::PublicKey(ref public_key) => {
    //             let verification_algorithm: &dyn signature::VerificationAlgorithm = match algorithm
    //             {
    //                 Algorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
    //                 Algorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
    //                 Algorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
    //                 Algorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
    //                 Algorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
    //                 Algorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
    //                 Algorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED,
    //                 Algorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED,
    //                 Algorithm::ES512 => Err(Error::UnsupportedOperation)?,
    //                 _ => unreachable!("Should not happen"),
    //             };

    //             let public_key = signature::UnparsedPublicKey::new(
    //                 verification_algorithm,
    //                 public_key.as_slice(),
    //             );
    //             public_key.verify(data, expected_signature)?;
    //             Ok(())
    //         }
    //         Secret::RsaKeyPair(ref keypair) => {
    //             let verification_algorithm: &dyn signature::VerificationAlgorithm = match algorithm
    //             {
    //                 Algorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
    //                 Algorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
    //                 Algorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
    //                 Algorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
    //                 Algorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
    //                 Algorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
    //                 _ => unreachable!("Should not happen"),
    //             };

    //             let public_key =
    //                 signature::UnparsedPublicKey::new(verification_algorithm, keypair.public_key());
    //             public_key.verify(data, expected_signature)?;
    //             Ok(())
    //         }
    //         Secret::RSAModulusExponent { ref n, ref e } => {
    //             let params = match algorithm {
    //                 Algorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
    //                 Algorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
    //                 Algorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
    //                 Algorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
    //                 Algorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
    //                 Algorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
    //                 _ => unreachable!("(n,e) secret with a non-rsa algorithm should not happen"),
    //             };

    //             let n_big_endian = n.to_bytes_be();
    //             let e_big_endian = e.to_bytes_be();
    //             let public_key = signature::RsaPublicKeyComponents {
    //                 n: n_big_endian,
    //                 e: e_big_endian,
    //             };
    //             public_key.verify(params, data, expected_signature)?;
    //             Ok(())
    //         }
    //         Secret::EcdsaKeyPair(ref keypair) => {
    //             let verification_algorithm: &dyn signature::VerificationAlgorithm = match algorithm
    //             {
    //                 Algorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED,
    //                 Algorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED,
    //                 Algorithm::ES512 => Err(Error::UnsupportedOperation)?,
    //                 _ => unreachable!("Should not happen"),
    //             };

    //             let public_key =
    //                 signature::UnparsedPublicKey::new(verification_algorithm, keypair.public_key());
    //             public_key.verify(data, expected_signature)?;
    //             Ok(())
    //         }
    //         _ => unreachable!("This is a private method and should not be called erroneously."),
    //     }
    // }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::jws::Secret;

//     #[test]
//     fn sign_and_verify_none() {
//         let expected_signature: Vec<u8> = vec![];
//         let actual_signature = Algorithm::None
//             .sign("payload".to_string().as_bytes(), &Secret::None)
//             .unwrap();
//         assert_eq!(expected_signature, actual_signature);

//         Algorithm::None
//             .verify(
//                 vec![].as_slice(),
//                 "payload".to_string().as_bytes(),
//                 &Secret::None,
//             )
//             .unwrap();
//     }

//     /// To generate the signature, use
//     ///
//     /// ```sh
//     /// echo -n "payload" | openssl dgst -sha256 -sign test/fixtures/rsa_private_key.pem | base64
//     /// ```
//     ///
//     /// The base64 encoding from this command will be in `STANDARD` form and not URL_SAFE.
//     #[test]
//     fn sign_and_verify_rs256() {
//         let private_key =
//             Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();
//         let payload = "payload".to_string();
//         let payload_bytes = payload.as_bytes();
//         // This is standard base64
//         let expected_signature =
//             "JIHqiBfUknrFPDLT0gxyoufD06S43ZqWN_PzQqHZqQ-met7kZmkSTYB_rUyotLMxlKkuXdnvKmWm\
//              dwGAHWEwDvb5392pCmAAtmUIl6LormxJptWYb2PoF5jmtX_lwV8y4RYIh54Ai51162VARQCKAsxL\
//              uH772MEChkcpjd31NWzaePWoi_IIk11iqy6uFWmbLLwzD_Vbpl2C6aHR3vQjkXZi05gA3zksjYAh\
//              j-m7GgBt0UFOE56A4USjhQwpb4g3NEamgp51_kZ2ULi4Aoo_KJC6ynIm_pR6rEzBgwZjlCUnE-6o\
//              5RPQZ8Oau03UDVH2EwZe-Q91LaWRvkKjGg5Tcw";
//         let expected_signature_bytes: Vec<u8> =
//             base64::decode_config(&expected_signature, base64::URL_SAFE_NO_PAD).unwrap();

//         let actual_signature = Algorithm::RS256.sign(payload_bytes, &private_key).unwrap();
//         assert_eq!(
//             base64::encode_config(&actual_signature, base64::URL_SAFE_NO_PAD),
//             expected_signature
//         );

//         let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
//         Algorithm::RS256
//             .verify(
//                 expected_signature_bytes.as_slice(),
//                 payload_bytes,
//                 &public_key,
//             )
//             .unwrap();
//     }

//     #[test]
//     fn sign_and_verify_rs256_key_params() {
//         use num_bigint::BigUint;
//         // There is no way in Ring right now to get these values from the key
//         let params = Secret::RSAModulusExponent {
//             n: BigUint::parse_bytes(
//                 b"D57336432EDB91A0A98E3BC2959C08D79017CBDF7AEA6EDCDEC611DA746E1\
//                                       DBD144FB4391163E797FB392C438CC70AEA89796D8FCFF69646655AD02E00\
//                                       169B5F1C4C9150D3399D80DCE6D8F6F057B105F5FC5EE774B0A8FF20A67D8\
//                                       0E6707D380462D2CDCB913E6EE9EA7585CD504AE45B6930BC713D02999E36\
//                                       BF449CFFA2385374F3850819056207880A2E8BA47EE8A86CBE4C361D6D54B\
//                                       95F2E1668262F79C2774D4234B8D5C6D15A0E95493E308AA98F002A78BB92\
//                                       8CB78F1E7E06243AB6D7EAFAB59F6446774B0479F6593F88F763978F14EFB\
//                                       7F422B4C66E8EB53FF5E6DC4D3C92952D8413E06E2D9EB1DF50D8224FF3BD\
//                                       319FF5E4258D06C578B9527B",
//                 16,
//             )
//             .unwrap(),
//             e: BigUint::from(65537u32),
//         };
//         let payload = "payload".to_string();
//         let payload_bytes = payload.as_bytes();
//         let expected_signature =
//             "JIHqiBfUknrFPDLT0gxyoufD06S43ZqWN_PzQqHZqQ-met7kZmkSTYB_rUyotLMxlKkuXdnvKmWm\
//              dwGAHWEwDvb5392pCmAAtmUIl6LormxJptWYb2PoF5jmtX_lwV8y4RYIh54Ai51162VARQCKAsxL\
//              uH772MEChkcpjd31NWzaePWoi_IIk11iqy6uFWmbLLwzD_Vbpl2C6aHR3vQjkXZi05gA3zksjYAh\
//              j-m7GgBt0UFOE56A4USjhQwpb4g3NEamgp51_kZ2ULi4Aoo_KJC6ynIm_pR6rEzBgwZjlCUnE-6o\
//              5RPQZ8Oau03UDVH2EwZe-Q91LaWRvkKjGg5Tcw";
//         let expected_signature_bytes: Vec<u8> =
//             base64::decode_config(expected_signature, base64::URL_SAFE_NO_PAD).unwrap();

//         Algorithm::RS256
//             .verify(expected_signature_bytes.as_slice(), payload_bytes, &params)
//             .unwrap();
//     }

//     /// This signature is non-deterministic.
//     #[test]
//     fn sign_and_verify_ps256_round_trip() {
//         let private_key =
//             Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();
//         let payload = "payload".to_string();
//         let payload_bytes = payload.as_bytes();

//         let actual_signature = Algorithm::PS256.sign(payload_bytes, &private_key).unwrap();

//         let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
//         Algorithm::PS256
//             .verify(actual_signature.as_slice(), payload_bytes, &public_key)
//             .unwrap();
//     }

//     /// This signature is non-deterministic.
//     #[test]
//     fn sign_and_verify_ps256_round_trip_with_keypair() {
//         let key = Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();
//         let payload = "payload".to_string();
//         let payload_bytes = payload.as_bytes();

//         let actual_signature = Algorithm::PS256.sign(payload_bytes, &key).unwrap();

//         Algorithm::PS256
//             .verify(actual_signature.as_slice(), payload_bytes, &key)
//             .unwrap();
//     }

//     /// To generate a (non-deterministic) signature:
//     ///
//     /// ```sh
//     /// echo -n "payload" | openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
//     ///    -sign test/fixtures/rsa_private_key.pem | base64
//     /// ```
//     ///
//     /// The base64 encoding from this command will be in `STANDARD` form and not URL_SAFE.
//     #[test]
//     fn verify_ps256() {
//         let payload = "payload".to_string();
//         let payload_bytes = payload.as_bytes();
//         let signature =
//             "TiMXtt3Wmv/a/tbLWuJPDlFYMfuKsD7U5lbBUn2mBu8DLMLj1EplEZNmkB8w65BgUijnu9hxmhwv\
//              ET2k7RrsYamEst6BHZf20hIK1yE/YWaktbVmAZwUDdIpXYaZn8ukTsMT06CDrVk6RXF0EPMaSL33\
//              tFNPZpz4/3pYQdxco/n6DpaR5206wsur/8H0FwoyiFKanhqLb1SgZqyc+SXRPepjKc28wzBnfWl4\
//              mmlZcJ2xk8O2/t1Y1/m/4G7drBwOItNl7EadbMVCetYnc9EILv39hjcL9JvaA9q0M2RB75DIu8SF\
//              9Kr/l+wzUJjWAHthgqSBpe15jLkpO8tvqR89fw==";
//         let signature_bytes: Vec<u8> = base64::decode(signature.as_bytes()).unwrap();
//         let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
//         Algorithm::PS256
//             .verify(signature_bytes.as_slice(), payload_bytes, &public_key)
//             .unwrap();
//     }

//     /// This signature is non-deterministic.
//     #[test]
//     fn sign_and_verify_es256_round_trip_with_keypair() {
//         let key =
//             Secret::ecdsa_keypair_from_file(Algorithm::ES256, "test/fixtures/ecdsa_private_key.p8")
//                 .unwrap();
//         let payload = "payload".to_string();
//         let payload_bytes = payload.as_bytes();

//         let actual_signature = Algorithm::ES256.sign(payload_bytes, &key).unwrap();

//         Algorithm::ES256
//             .verify(actual_signature.as_slice(), payload_bytes, &key)
//             .unwrap();
//     }

//     #[test]
//     #[should_panic(expected = "UnspecifiedCryptographicError")]
//     fn invalid_rs256() {
//         let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
//         let invalid_signature = "broken".to_string();
//         let signature_bytes = invalid_signature.as_bytes();
//         Algorithm::RS256
//             .verify(
//                 signature_bytes,
//                 "payload".to_string().as_bytes(),
//                 &public_key,
//             )
//             .unwrap();
//     }

//     #[test]
//     #[should_panic(expected = "UnspecifiedCryptographicError")]
//     fn invalid_ps256() {
//         let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
//         let invalid_signature = "broken".to_string();
//         let signature_bytes = invalid_signature.as_bytes();
//         Algorithm::PS256
//             .verify(
//                 signature_bytes,
//                 "payload".to_string().as_bytes(),
//                 &public_key,
//             )
//             .unwrap();
//     }

// }
