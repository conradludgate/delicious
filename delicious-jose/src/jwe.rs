//! [JSON Web Encryption](https://tools.ietf.org/html/rfc7516)
//!
//! This module contains code to implement JWE, the JOSE standard to encrypt arbitrary payloads.
//! Most commonly, JWE is used to encrypt a JWS payload, which is a signed JWT. For most common use,
//! you will want to look at the  [`Compact`](enum.Compact.html) enum.
use std::borrow::Cow;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use rand::RngCore;
use serde::de::{self, DeserializeOwned};
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

use crate::errors::{Error, ValidationError};
use crate::jwa::{self, kma, ContentEncryptionAlgorithm, EncryptionResult};
use crate::CompactPart;

#[derive(Debug, Eq, PartialEq, Clone)]
/// Compression algorithm applied to plaintext before encryption.
pub enum CompressionAlgorithm {
    /// DEFLATE algorithm defined in [RFC 1951](https://tools.ietf.org/html/rfc1951)
    Deflate,
    /// Other user-defined algorithm
    Other(String),
}

impl Serialize for CompressionAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string = match *self {
            CompressionAlgorithm::Deflate => "DEF",
            CompressionAlgorithm::Other(ref other) => other,
        };

        serializer.serialize_str(string)
    }
}

impl<'de> Deserialize<'de> for CompressionAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CompressionAlgorithmVisitor;
        impl<'de> de::Visitor<'de> for CompressionAlgorithmVisitor {
            type Value = CompressionAlgorithm;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(match v {
                    "DEF" => CompressionAlgorithm::Deflate,
                    other => CompressionAlgorithm::Other(other.to_string()),
                })
            }
        }

        deserializer.deserialize_string(CompressionAlgorithmVisitor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
/// Registered JWE header fields.
/// The fields are defined by [RFC 7516#4.1](https://tools.ietf.org/html/rfc7516#section-4.1)
pub struct RegisteredHeader {
    /// Algorithm used to encrypt or determine the value of the Content Encryption Key
    #[serde(rename = "alg")]
    pub cek_algorithm: kma::Algorithm,

    /// Content encryption algorithm used to perform authenticated encryption
    /// on the plaintext to produce the ciphertext and the Authentication Tag
    #[serde(rename = "enc")]
    pub enc_algorithm: ContentEncryptionAlgorithm,

    /// Compression algorithm applied to plaintext before encryption, if any.
    /// Compression is not supported at the moment.
    /// _Must only appear in integrity protected header._
    #[serde(rename = "zip", skip_serializing_if = "Option::is_none")]
    pub compression_algorithm: Option<CompressionAlgorithm>,

    /// Media type of the complete JWE. Serialized to `typ`.
    /// Defined in [RFC7519#5.1](https://tools.ietf.org/html/rfc7519#section-5.1) and additionally
    /// [RFC7515#4.1.9](https://tools.ietf.org/html/rfc7515#section-4.1.9).
    /// The "typ" value "JOSE" can be used by applications to indicate that
    /// this object is a JWS or JWE using the JWS Compact Serialization or
    /// the JWE Compact Serialization.  The "typ" value "JOSE+JSON" can be
    /// used by applications to indicate that this object is a JWS or JWE
    /// using the JWS JSON Serialization or the JWE JSON Serialization.
    /// Other type values can also be used by applications.
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// Content Type of the secured payload.
    /// Typically used to indicate the presence of a nested JOSE object which is signed or encrypted.
    /// Serialized to `cty`.
    /// Defined in [RFC7519#5.2](https://tools.ietf.org/html/rfc7519#section-5.2) and additionally
    /// [RFC7515#4.1.10](https://tools.ietf.org/html/rfc7515#section-4.1.10).
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// The JSON Web Key Set URL. This is currently not implemented (correctly).
    /// Serialized to `jku`.
    /// Defined in [RFC7515#4.1.2](https://tools.ietf.org/html/rfc7515#section-4.1.2).
    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    pub web_key_url: Option<String>,

    /// The JSON Web Key. This is currently not implemented (correctly).
    /// Serialized to `jwk`.
    /// Defined in [RFC7515#4.1.3](https://tools.ietf.org/html/rfc7515#section-4.1.3).
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub web_key: Option<String>,

    /// The Key ID. This is currently not implemented (correctly).
    /// Serialized to `kid`.
    /// Defined in [RFC7515#4.1.3](https://tools.ietf.org/html/rfc7515#section-4.1.3).
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// X.509 Public key cerfificate URL. This is currently not implemented (correctly).
    /// Serialized to `x5u`.
    /// Defined in [RFC7515#4.1.5](https://tools.ietf.org/html/rfc7515#section-4.1.5).
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<String>,

    /// X.509 public key certificate chain. This is currently not implemented (correctly).
    /// Serialized to `x5c`.
    /// Defined in [RFC7515#4.1.6](https://tools.ietf.org/html/rfc7515#section-4.1.6).
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub x509_chain: Option<Vec<String>>,

    /// X.509 Certificate thumbprint. This is currently not implemented (correctly).
    /// Also not implemented, is the SHA-256 thumbprint variant of this header.
    /// Serialized to `x5t`.
    /// Defined in [RFC7515#4.1.7](https://tools.ietf.org/html/rfc7515#section-4.1.7).
    // TODO: How to make sure the headers are mutually exclusive?
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub x509_fingerprint: Option<String>,

    /// List of critical extended headers.
    /// This is currently not implemented (correctly).
    /// Serialized to `crit`.
    /// Defined in [RFC7515#4.1.11](https://tools.ietf.org/html/rfc7515#section-4.1.11).
    #[serde(rename = "crit", skip_serializing_if = "Option::is_none")]
    pub critical: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
/// Headers specific to the Key management algorithm used. Users should typically not construct these fields as they
/// will be filled in automatically when encrypting and stripped when decrypting
pub struct CekAlgorithmHeader {
    /// Header for AES GCM Keywrap algorithm.
    /// The initialization vector, or nonce used in the encryption
    #[serde(rename = "iv", skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Vec<u8>>,

    /// Header for AES GCM Keywrap algorithm.
    /// The authentication tag resulting from the encryption
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<Vec<u8>>,

    /// Header for PBES2 algorithm.
    /// PBKDF iteration count
    #[serde(rename = "p2c", skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,

    /// Header for PBES2 algorithm.
    /// PBKDF salt
    #[serde(rename = "p2s", skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
}

/// JWE Header, consisting of the registered fields and other custom fields
#[derive(Debug, Eq, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct Header<KmaHeader, T = ()> {
    /// Registered header fields
    #[serde(flatten)]
    pub registered: RegisteredHeader,
    /// Key management algorithm specific headers
    #[serde(flatten)]
    pub kma: KmaHeader,
    /// Private header fields
    #[serde(flatten)]
    pub private: T,
}

impl<KmaHeader, T> CompactPart for Header<KmaHeader, T>
where
    KmaHeader: Serialize + DeserializeOwned,
    T: Serialize + DeserializeOwned,
{
    fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(serde_json::from_slice(b)?)
    }

    fn to_bytes(&self) -> Result<Cow<'_, [u8]>, Error> {
        Ok(serde_json::to_vec(&self)?.into())
    }
}

impl Header<()> {
    /// Convenience function to create a header with only registered headers
    pub fn from_registered_header(registered: RegisteredHeader) -> Self {
        Self {
            registered,
            ..Default::default()
        }
    }
}

impl From<RegisteredHeader> for Header<(), ()> {
    fn from(registered: RegisteredHeader) -> Self {
        Self::from_registered_header(registered)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted<KMA: kma::KMA, H = ()> {
    header: Header<KMA::Header, H>,
    header_base64: String,
    encrypted_cek: Vec<u8>,
    iv: Vec<u8>,
    encrypted_payload: Vec<u8>,
    tag: Vec<u8>,
}

impl<KMA, H> CompactPart for Encrypted<KMA, H>
where
    KMA: kma::KMA,
    H: DeserializeOwned,
{
    fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        std::str::from_utf8(b)?.parse()
    }

    fn to_bytes(&self) -> Result<Cow<'_, [u8]>, Error> {
        Ok(self.to_string().into_bytes().into())
    }
}

impl<KMA: kma::KMA, H: Serialize> Serialize for Encrypted<KMA, H> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de, KMA: kma::KMA, H: DeserializeOwned> Deserialize<'de> for Encrypted<KMA, H> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EncryptedVisitor<KMA, H>(PhantomData<(KMA, H)>);

        impl<'de, KMA: kma::KMA, H: DeserializeOwned> de::Visitor<'de> for EncryptedVisitor<KMA, H> {
            type Value = Encrypted<KMA, H>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string containing a compact JOSE representation of a JWE")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(EncryptedVisitor(PhantomData))
    }
}

impl<KMA: kma::KMA, H> fmt::Display for Encrypted<KMA, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.header_base64)?;
        let mut buf = [0; 1024];
        let parts = [
            &self.encrypted_cek,
            &self.iv,
            &self.encrypted_payload,
            &self.tag,
        ];
        for part in parts {
            f.write_str(".")?;
            for chunk in part.chunks(1024 / 4 * 3) {
                let n = base64::encode_config_slice(chunk, base64::URL_SAFE_NO_PAD, &mut buf);
                let s = unsafe { std::str::from_utf8_unchecked(&buf[..n]) };
                f.write_str(s)?
            }
        }
        Ok(())
    }
}

impl<KMA, H> FromStr for Encrypted<KMA, H>
where
    KMA: kma::KMA,
    H: DeserializeOwned,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut sections = [""; 5];
        let mut split = s.split('.');
        for (i, section) in sections.iter_mut().enumerate() {
            *section = split.next().ok_or(Error::DecodeError(
                crate::errors::DecodeError::PartsLengthError {
                    expected: 5,
                    actual: i,
                },
            ))?
        }
        let rest = split.count();
        if rest > 0 {
            return Err(Error::DecodeError(
                crate::errors::DecodeError::PartsLengthError {
                    expected: 5,
                    actual: 5 + rest,
                },
            ));
        }
        let [header_base64, cek, iv, payload, tag] = sections;

        let header = base64::decode_config(header_base64, base64::URL_SAFE_NO_PAD)?;
        let header = serde_json::from_slice(&header)?;
        Ok(Self {
            header,
            header_base64: header_base64.to_owned(),
            encrypted_cek: Vec::from_base64(cek)?,
            iv: Vec::from_base64(iv)?,
            encrypted_payload: Vec::from_base64(payload)?,
            tag: Vec::from_base64(tag)?,
        })
    }
}

impl<KMA, H> Encrypted<KMA, H>
where
    KMA: kma::KMA,
    H: Serialize + DeserializeOwned,
{
    // Decrypt an encrypted JWE. Provide the expected algorithms to mitigate an attacker modifying the
    /// fields
    pub fn decrypt<T, CEA>(self, key: &KMA::Key) -> Result<Decrypted<T, H>, Error>
    where
        CEA: jwa::cea::CEA<Cek = KMA::Cek>,
        T: CompactPart,
    {
        let Self {
            header,
            header_base64,
            encrypted_cek,
            iv,
            encrypted_payload,
            tag,
        } = self;

        // Verify that the algorithms are expected
        if header.registered.cek_algorithm != KMA::ALG
            || header.registered.enc_algorithm != CEA::ENC
        {
            Err(Error::ValidationError(
                ValidationError::WrongAlgorithmHeader,
            ))?;
        }

        // TODO: Steps 4-5 not implemented at the moment.

        // Steps 6-13 involve the computation of the cek
        let cek = KMA::unwrap(&encrypted_cek, key, header.kma)?;

        // Build encryption result as per steps 14-15
        let encrypted_payload_result = EncryptionResult {
            nonce: iv,
            tag,
            encrypted: encrypted_payload,
            additional_data: header_base64.into_bytes(),
        };
        let payload = CEA::decrypt(&cek, &encrypted_payload_result)?;

        // Decompression is not supported at the moment
        if header.registered.compression_algorithm.is_some() {
            Err(Error::UnsupportedOperation)?
        }

        let payload = T::from_bytes(&payload)?;

        Ok(Decrypted::new_with_header(header.private, payload))
    }
}

/// Rust representation of a JWE
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decrypted<T, H = ()> {
    /// Embedded header
    pub header: H,
    /// Payload, usually a signed/unsigned JWT
    pub payload: T,
}

impl<T> Decrypted<T> {
    /// Create a new JWE
    pub fn new(payload: T) -> Self {
        Self::new_with_header((), payload)
    }
}

impl<T> Decrypted<crate::Json<T>> {
    /// Create a new json JWE
    pub fn new_json(payload: T) -> Self {
        Self::new(crate::Json(payload))
    }
}

impl<T, H> Decrypted<T, H> {
    /// Create a new JWE with a custom header field
    pub fn new_with_header(header: H, payload: T) -> Self {
        Self { header, payload }
    }
}

impl<T, H> Decrypted<T, H>
where
    T: CompactPart,
    H: Serialize + DeserializeOwned,
{
    /// Encrypt an Decrypted JWE.
    ///
    /// You will need to provide a `jwa::EncryptionOptions` that will differ based on your chosen
    /// algorithms.
    ///
    /// If your `cek_algorithm` is not `dir` or direct, the options provided will be used to
    /// encrypt your content encryption key.
    ///
    /// If your `cek_algorithm` is `dir` or Direct, then the options will be used to encrypt
    /// your content directly.
    pub fn encrypt<CEA, KMA>(
        self,
        key: &KMA::Key,
        key_settings: KMA::WrapSettings,
    ) -> Result<Encrypted<KMA, H>, Error>
    where
        CEA: jwa::cea::CEA,
        KMA: jwa::kma::KMA<Cek = CEA::Cek>,
    {
        // RFC 7516 Section 5.1 describes the steps involved in encryption.
        // From steps 1 to 8, we will first determine the CEK, and then encrypt the CEK.
        let cek = KMA::generate_key::<CEA>(key);
        let (encrypted_cek, cea_header) = KMA::wrap(&cek, key, key_settings)?;

        // Steps 9 and 10 involves calculating an initialization vector (nonce) for content encryption.
        let mut iv = vec![0; CEA::IV];
        rand::thread_rng().fill_bytes(&mut iv);

        // Step 11 involves compressing the payload, which we do not support at the moment
        let payload = self.payload.to_bytes()?;
        // if self.header.registered.compression_algorithm.is_some() {
        //     Err(Error::UnsupportedOperation)?;
        // }

        // Steps 12 to 14 involves the calculation of `Additional Authenticated Data` for encryption. In
        // our compact example, our header is the AAD.
        let header = Header {
            kma: cea_header,
            registered: RegisteredHeader {
                cek_algorithm: KMA::ALG,
                enc_algorithm: CEA::ENC,
                ..Default::default()
            },
            private: self.header,
        };
        let encoded_protected_header = header.to_base64()?;

        // Step 15 involves the actual encryption.
        let encrypted = CEA::encrypt(
            &cek,
            &payload,
            iv,
            encoded_protected_header.as_bytes().to_vec(),
        )?;

        // Finally create the JWE
        Ok(Encrypted {
            header_base64: encoded_protected_header.into_owned(),
            header,
            encrypted_cek,
            iv: encrypted.nonce,
            encrypted_payload: encrypted.encrypted,
            tag: encrypted.tag,
        })
    }
}

/// Convenience implementation for a Compact that contains a `ClaimsSet`
impl<P, H> Decrypted<crate::ClaimsSet<P>, H>
where
    crate::ClaimsSet<P>: Serialize + DeserializeOwned,
    H: Serialize + DeserializeOwned + Clone,
{
    /// Validate the temporal claims in the decoded token
    ///
    /// If `None` is provided for options, the defaults will apply.
    ///
    /// By default, no temporal claims (namely `iat`, `exp`, `nbf`)
    /// are required, and they will pass validation if they are missing.
    pub fn validate(&self, options: crate::ValidationOptions) -> Result<(), Error> {
        self.payload.registered.validate(options)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // use std::str::FromStr;

    use serde_test::{assert_tokens, Token};

    use super::*;
    use crate::jwa::{self, cea};
    use crate::test::assert_serde_json;
    use crate::{jwk, jws, Json};

    pub fn random_vec(len: usize) -> Vec<u8> {
        let mut nonce = vec![0; len];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    pub fn random_aes_gcm_nonce() -> Vec<u8> {
        random_vec(12)
    }

    fn cek_oct_key(len: usize) -> jwa::OctetKey {
        jwa::OctetKey::new(random_vec(len))
    }

    #[test]
    fn compression_algorithm_serde_token() {
        #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
        struct Test {
            test: CompressionAlgorithm,
        }

        let test_value = Test {
            test: CompressionAlgorithm::Deflate,
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("DEF"),
                Token::StructEnd,
            ],
        );

        let test_value = Test {
            test: CompressionAlgorithm::Other("xxx".to_string()),
        };
        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "Test",
                    len: 1,
                },
                Token::Str("test"),
                Token::Str("xxx"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn compression_algorithm_json_serde() {
        #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
        struct Test {
            test: CompressionAlgorithm,
        }

        let test_json = r#"{"test": "DEF"}"#;
        assert_serde_json(
            &Test {
                test: CompressionAlgorithm::Deflate,
            },
            Some(test_json),
        );

        let test_json = r#"{"test": "xxx"}"#;
        assert_serde_json(
            &Test {
                test: CompressionAlgorithm::Other("xxx".to_string()),
            },
            Some(test_json),
        );
    }

    #[test]
    fn jwe_interoperability_check() {
        // This test vector is created by using python-jwcrypto (https://jwcrypto.readthedocs.io/en/latest/)
        /*
          from jwcrypto import jwk, jwe
          from jwcrypto.common import json_encode
          key = jwk.JWK.generate(kty='oct', size=256)
          payload = '"Encrypted"'
          jwetoken = jwe.JWE(payload.encode('utf-8'),
                             json_encode({"alg": "dir",
                                          "enc": "A256GCM"}))
          jwetoken.add_recipient(key)
          jwetoken.serialize()
          key.export()
        */
        let external_token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..fHhEyBZ9S4CsGi1Y.gnTZjScRZu22rvk.F8SJn0TUAus8w_TaItsOJw";
        let key_json = r#"{"k":"-wcjSeVOJ0V43ij5uDBeFlOR1w2T40jqIfICQb8-sUw","kty":"oct"}"#;

        let key: jwk::JWK<()> = serde_json::from_str(key_json).unwrap();
        let key = key.specified.try_into().unwrap();
        let token: Encrypted<kma::DirectEncryption> = external_token.parse().unwrap();

        let decrypted_jwe = token.decrypt::<Json<String>, cea::A256GCM>(&key).unwrap();

        let decrypted_payload = decrypted_jwe.payload;
        assert_eq!(decrypted_payload.0, "Encrypted");
    }

    #[test]
    fn jwe_header_round_trips() {
        let test_value: Header<()> = From::from(RegisteredHeader {
            cek_algorithm: kma::Algorithm::RSA_OAEP,
            enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
            ..Default::default()
        });
        let test_json = r#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#;
        assert_serde_json(&test_value, Some(test_json));

        let test_value: Header<()> = From::from(RegisteredHeader {
            cek_algorithm: kma::Algorithm::RSA1_5,
            enc_algorithm: ContentEncryptionAlgorithm::A128CBC_HS256,
            ..Default::default()
        });
        let test_json = r#"{"alg":"RSA1_5","enc":"A128CBC-HS256"}"#;
        assert_serde_json(&test_value, Some(test_json));

        let test_value: Header<()> = From::from(RegisteredHeader {
            cek_algorithm: kma::Algorithm::A128KW,
            enc_algorithm: ContentEncryptionAlgorithm::A128CBC_HS256,
            ..Default::default()
        });
        let test_json = r#"{"alg":"A128KW","enc":"A128CBC-HS256"}"#;
        assert_serde_json(&test_value, Some(test_json));
    }

    #[test]
    fn custom_jwe_header_round_trip() {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct CustomHeader {
            something: String,
        }

        let test_value = Header {
            registered: RegisteredHeader {
                cek_algorithm: kma::Algorithm::RSA_OAEP,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            },
            kma: (),
            private: CustomHeader {
                something: "foobar".to_string(),
            },
        };
        let test_json = r#"{"alg":"RSA-OAEP","enc":"A256GCM","something":"foobar"}"#;
        assert_serde_json(&test_value, Some(test_json));
    }

    #[test]
    fn jwe_a256gcmkw_a256gcm_string_round_trip() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload =
            String::from("The true sign of intelligence is not knowledge but imagination.");
        let jwe = Decrypted::new(Json(payload.clone()));
        let cek_nonce = random_aes_gcm_nonce();

        // Encrypt
        let encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        {
            // Check that new header values are added
            let header = &encrypted_jwe.header;
            assert!(!header.kma.nonce.is_empty());
            assert!(!header.kma.tag.is_empty());

            // Check that the encrypted key part is not empty
            assert_eq!(256 / 8, encrypted_jwe.encrypted_cek.len());
        }

        // Serde test
        let json = serde_json::to_string(&encrypted_jwe).unwrap();
        let deserialized_json: Encrypted<kma::A256GCMKW> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized_json, encrypted_jwe);

        // Decrypt
        let decrypted_jwe = encrypted_jwe
            .decrypt::<Json<String>, cea::A256GCM>(&key)
            .unwrap();
        assert_eq!(payload, decrypted_jwe.payload.0);
    }

    #[test]
    fn jwe_a256gcmkw_a256gcm_jws_round_trip() {
        // Construct the JWS
        let claims = crate::ClaimsSet::<()> {
            registered: crate::RegisteredClaims {
                issuer: Some(FromStr::from_str("https://www.acme.com").unwrap()),
                subject: Some(FromStr::from_str("John Doe").unwrap()),
                audience: Some(crate::SingleOrMultiple::Single(
                    FromStr::from_str("htts://acme-customer.com").unwrap(),
                )),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: Default::default(),
        };
        let jws = jws::Decoded::new(
            From::from(jws::RegisteredHeader {
                algorithm: jwa::SignatureAlgorithm::HS256,
                ..Default::default()
            }),
            claims,
        );
        let jws = jws
            .encode(&jws::Secret::Bytes("secret".to_string().into_bytes()))
            .unwrap();

        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let jwe = Decrypted::new(jws.clone());
        let cek_nonce = random_aes_gcm_nonce();

        // Encrypt
        let encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        {
            // Check that new header values are added
            let header = &encrypted_jwe.header;
            assert!(!header.kma.nonce.is_empty());
            assert!(!header.kma.tag.is_empty());

            // Check that the encrypted key part is not empty
            assert_eq!(256 / 8, encrypted_jwe.encrypted_cek.len());
        }

        // Serde test
        let json = serde_json::to_string(&encrypted_jwe).unwrap();
        let deserialized_json: Encrypted<kma::A256GCMKW> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized_json, encrypted_jwe);

        // Decrypt
        let decrypted_jwe = encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
        assert_eq!(jws, decrypted_jwe.payload);
    }

    #[test]
    fn jwe_dir_aes256gcm_jws_round_trip() {
        // Construct the JWS
        let claims = crate::ClaimsSet::<()> {
            registered: crate::RegisteredClaims {
                issuer: Some(FromStr::from_str("https://www.acme.com").unwrap()),
                subject: Some(FromStr::from_str("John Doe").unwrap()),
                audience: Some(crate::SingleOrMultiple::Single(
                    FromStr::from_str("htts://acme-customer.com").unwrap(),
                )),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: Default::default(),
        };
        let jws = jws::Decoded::new(
            From::from(jws::RegisteredHeader {
                algorithm: jwa::SignatureAlgorithm::HS256,
                ..Default::default()
            }),
            claims,
        );
        let jws = jws
            .encode(&jws::Secret::Bytes("secret".to_string().into_bytes()))
            .unwrap();

        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let jwe = Decrypted::new(jws.clone());

        // Encrypt
        let encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::DirectEncryption>(&key, ())
            .unwrap();

        // Check that the encrypted key part is empty
        assert!(encrypted_jwe.encrypted_cek.is_empty());

        // Serde test
        let json = serde_json::to_string(&encrypted_jwe).unwrap();
        let deserialized_json: Encrypted<kma::DirectEncryption> =
            serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized_json, encrypted_jwe);

        // Decrypt
        let decrypted_jwe = encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
        assert_eq!(jws, decrypted_jwe.payload);
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn decrypt_with_mismatch_cek_algorithm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(payload.as_bytes().to_vec());
        let cek_nonce = random_aes_gcm_nonce();

        // Encrypt
        let encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // reparse it as a A128GCMKW jwe
        let encrypted_jwe: Encrypted<kma::A128GCMKW> = encrypted_jwe.to_string().parse().unwrap();

        let _ = encrypted_jwe
            .decrypt::<Vec<u8>, cea::A256GCM>(&key)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn decrypt_with_mismatch_enc_algorithm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(payload.as_bytes().to_vec());
        let cek_nonce = random_aes_gcm_nonce();

        // Encrypt
        let encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        let _ = encrypted_jwe
            .decrypt::<Vec<u8>, cea::A128GCM>(&key)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "PartsLengthError")]
    fn decrypt_with_incorrect_length() {
        let _: Encrypted<kma::DirectEncryption> = "INVALID".parse().unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_nonce_for_aes256gcmkw() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(payload.as_bytes().to_vec());
        let cek_nonce = random_aes_gcm_nonce();

        // Encrypt
        let mut encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Modify the JWE
        encrypted_jwe.header.kma.nonce = vec![0; 96 / 8];
        encrypted_jwe.header_base64 = encrypted_jwe.header.to_base64().unwrap().into_owned();

        // Decrypt
        let _ = encrypted_jwe
            .decrypt::<Vec<u8>, cea::A256GCM>(&key)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_tag_for_aes256gcmkw() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(payload.as_bytes().to_vec());
        let cek_nonce = random_aes_gcm_nonce();

        // Encrypt
        let mut encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Modify the JWE
        encrypted_jwe.header.kma.tag = vec![0; 96 / 8];
        encrypted_jwe.header_base64 = encrypted_jwe.header.to_base64().unwrap().into_owned();

        // Decrypt
        let _: Decrypted<Vec<u8>, ()> = encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_tag_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(payload.as_bytes().to_vec());
        let cek_nonce = random_aes_gcm_nonce();

        // Encrypt
        let mut encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Modify the JWE
        encrypted_jwe.tag = vec![0];

        // Decrypt
        let _: Decrypted<Vec<u8>, ()> = encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
    }

    /// This test modifies the header so the tag (aad for the AES GCM) included becomes incorrect
    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_modified_header_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(payload.as_bytes().to_vec());
        let cek_nonce = random_aes_gcm_nonce();

        // Encrypt
        let mut encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Modify the JWE
        encrypted_jwe.header.registered.media_type = Some("JOSE+JSON".to_string());
        encrypted_jwe.header_base64 = encrypted_jwe.header.to_base64().unwrap().into_owned();

        // Decrypt
        let _: Decrypted<Vec<u8>, ()> = encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
    }

    /// This test modifies the encrypted cek
    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_modified_encrypted_cek_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(payload.as_bytes().to_vec());
        let cek_nonce = random_aes_gcm_nonce();

        // Encrypt
        let mut encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Modify the JWE
        encrypted_jwe.encrypted_cek = vec![0u8; 256 / 8];

        // Decrypt
        let _: Decrypted<Vec<u8>, ()> = encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
    }

    /// This test modifies the encrypted payload
    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_modified_encrypted_payload_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(payload.as_bytes().to_vec());
        let cek_nonce = random_aes_gcm_nonce();

        // Encrypt
        let mut encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Modify the JWE
        encrypted_jwe.encrypted_payload = vec![0u8; 32];

        // Decrypt
        let _: Decrypted<Vec<u8>, ()> = encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
    }

    /// This test modifies the nonce
    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_modified_encrypted_nonce_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(payload.as_bytes().to_vec());
        let cek_nonce = random_aes_gcm_nonce();

        // Encrypt
        let mut encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Modify the JWE
        encrypted_jwe.iv = vec![0u8; 96 / 8];

        // Decrypt
        let _: Decrypted<Vec<u8>, ()> = encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
    }
}
