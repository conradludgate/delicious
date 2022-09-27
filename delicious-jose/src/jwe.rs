//! [JSON Web Encryption](https://tools.ietf.org/html/rfc7516)
//!
//! This module contains code to implement JWE, the JOSE standard to encrypt arbitrary payloads.
//! Most commonly, JWE is used to encrypt a JWS payload, which is a signed JWT. For most common use,
//! you will want to look at the  [`Compact`](enum.Compact.html) enum.
use std::borrow::Cow;
use std::fmt;

use serde::de::{self, DeserializeOwned};
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

use crate::errors::{DecodeError, Error, ValidationError};
use crate::jwa::{kma, ContentEncryptionAlgorithm, EncryptionOptions, EncryptionResult};
use crate::{jwk, Compact, CompactPart};

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
pub struct Header<T> {
    /// Registered header fields
    #[serde(flatten)]
    pub registered: RegisteredHeader,
    /// Key management algorithm specific headers
    #[serde(flatten)]
    pub cek_algorithm: CekAlgorithmHeader,
    /// Private header fields
    #[serde(flatten)]
    pub private: T,
}

impl<T: Serialize + DeserializeOwned> CompactPart for Header<T> {
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

impl From<RegisteredHeader> for Header<()> {
    fn from(registered: RegisteredHeader) -> Self {
        Self::from_registered_header(registered)
    }
}

pub struct Encrypted<H = ()> {
    header: Header<H>,
    header_base64: String,
    encrypted_cek: Vec<u8>,
    iv: Vec<u8>,
    encrypted_payload: Vec<u8>,
    tag: Vec<u8>,
}

impl<H> Encrypted<H>
where
    H: Serialize + DeserializeOwned + Clone,
{
    /// Turns the encrypted JWE into it's compact form
    pub fn compact(&self) -> Compact {
        let mut compact = Compact::new();
        compact.push_base64(&self.header_base64);
        compact.push_bytes(&self.encrypted_cek);
        compact.push_bytes(&self.iv);
        compact.push_bytes(&self.encrypted_payload);
        compact.push_bytes(&self.tag);
        compact
    }

    /// Decode and parse the compact form of JWE
    pub fn decode(s: &str) -> Result<Self, Error> {
        Compact::decode(s).try_into()
    }

    // Decrypt an encrypted JWE. Provide the expected algorithms to mitigate an attacker modifying the
    /// fields
    pub fn decrypt<T: CompactPart>(
        self,
        key: &jwk::Specified,
        cek_alg: kma::Algorithm,
        enc_alg: ContentEncryptionAlgorithm,
    ) -> Result<Decrypted<T, H>, Error> {
        let Self {
            mut header,
            header_base64,
            encrypted_cek,
            iv,
            encrypted_payload,
            tag,
        } = self;

        // Verify that the algorithms are expected
        if header.registered.cek_algorithm != cek_alg || header.registered.enc_algorithm != enc_alg
        {
            Err(Error::ValidationError(
                ValidationError::WrongAlgorithmHeader,
            ))?;
        }

        // TODO: Steps 4-5 not implemented at the moment.

        // Steps 6-13 involve the computation of the cek
        // let cek_encryption_result = header.extract_cek_encryption_result(&encrypted_cek);
        let cek = header.registered.cek_algorithm.unwrap_key(
            &encrypted_cek,
            &mut header.cek_algorithm,
            key,
        )?;

        // Build encryption result as per steps 14-15
        let encrypted_payload_result = EncryptionResult {
            nonce: iv,
            tag,
            encrypted: encrypted_payload,
            additional_data: header_base64.into_bytes(),
        };

        let payload = header
            .registered
            .enc_algorithm
            .decrypt(&encrypted_payload_result, &cek)?;

        // Decompression is not supported at the moment
        if header.registered.compression_algorithm.is_some() {
            Err(Error::UnsupportedOperation)?
        }

        let payload = T::from_bytes(&payload)?;

        Ok(Decrypted::new(header, payload))
    }
}

impl<H> TryFrom<Compact> for Encrypted<H>
where
    H: Serialize + DeserializeOwned + Clone,
{
    type Error = Error;

    fn try_from(encrypted: Compact) -> Result<Self, Self::Error> {
        if encrypted.len() != 5 {
            Err(DecodeError::PartsLengthError {
                actual: encrypted.len(),
                expected: 5,
            })?;
        }
        let header: Header<H> = encrypted.part(0)?;
        let encrypted_cek = encrypted.part(1)?;
        let iv = encrypted.part(2)?;
        let encrypted_payload = encrypted.part(3)?;
        let tag = encrypted.part(4)?;
        Ok(Self {
            header,
            header_base64: encrypted.part_base64(0)?.to_owned(),
            encrypted_cek,
            iv,
            encrypted_payload,
            tag,
        })
    }
}

/// Rust representation of a JWE
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decrypted<T, H = ()> {
    /// Embedded header
    pub header: Header<H>,
    /// Payload, usually a signed/unsigned JWT
    pub payload: T,
}

impl<T, H> Decrypted<T, H>
where
    T: CompactPart,
    H: Serialize + DeserializeOwned + Clone,
{
    /// Create a new encrypted JWE
    pub fn new(header: Header<H>, payload: T) -> Self {
        Self { header, payload }
    }

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
    pub fn encrypt(
        mut self,
        key: &jwk::Specified,
        options: &EncryptionOptions,
    ) -> Result<Encrypted<H>, Error> {
        // Resolve encryption option
        let content_option: Cow<'_, _> = match self.header.registered.cek_algorithm {
            kma::Algorithm::DirectSymmetricKey => Cow::Borrowed(options),
            _ => Cow::Owned(
                self.header
                    .registered
                    .enc_algorithm
                    .random_encryption_options()?,
            ),
        };

        // RFC 7516 Section 5.1 describes the steps involved in encryption.
        // From steps 1 to 8, we will first determine the CEK, and then encrypt the CEK.
        let cek = self
            .header
            .registered
            .cek_algorithm
            .cek(self.header.registered.enc_algorithm, key)?;
        let encrypted_cek = self.header.registered.cek_algorithm.wrap_key(
            cek.algorithm.octet_key()?,
            key,
            &mut self.header.cek_algorithm,
        )?;

        // Steps 9 and 10 involves calculating an initialization vector (nonce) for content encryption. We do
        // this as part of the encryption process later

        // Step 11 involves compressing the payload, which we do not support at the moment
        let payload = self.payload.to_bytes()?;
        if self.header.registered.compression_algorithm.is_some() {
            Err(Error::UnsupportedOperation)?;
        }

        // Steps 12 to 14 involves the calculation of `Additional Authenticated Data` for encryption. In
        // our compact example, our header is the AAD.
        let encoded_protected_header = self.header.to_base64()?;
        // Step 15 involves the actual encryption.
        let encrypted_payload = self.header.registered.enc_algorithm.encrypt(
            &payload,
            encoded_protected_header.as_bytes(),
            &cek,
            &content_option,
        )?;

        // Finally create the JWE
        Ok(Encrypted {
            header_base64: encoded_protected_header.into_owned(),
            header: self.header,
            encrypted_cek,
            iv: encrypted_payload.nonce,
            encrypted_payload: encrypted_payload.encrypted,
            tag: encrypted_payload.tag,
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
    use std::str::FromStr;

    use ring::rand::{SecureRandom, SystemRandom};
    use serde_test::{assert_tokens, Token};

    use super::*;
    use crate::jwa::{self, random_aes_gcm_nonce};
    use crate::test::assert_serde_json;
    use crate::{jws, Compact, Json};

    fn cek_oct_key(len: usize) -> jwk::Specified {
        // Construct the encryption key
        let mut key: Vec<u8> = vec![0; len];
        not_err!(SystemRandom::new().fill(&mut key));
        jwk::Specified {
            common: Default::default(),
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                key_type: Default::default(),
                value: key,
            }),
        }
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

        let key: jwk::JWK<()> = not_err!(serde_json::from_str(key_json));
        let token: Compact = Compact::decode(external_token);
        let token: Encrypted<()> = token.try_into().unwrap();

        let decrypted_jwe = not_err!(token.decrypt::<Json<String>>(
            &key.specified,
            kma::Algorithm::DirectSymmetricKey,
            jwa::ContentEncryptionAlgorithm::A256GCM,
        ));

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
            cek_algorithm: Default::default(),
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
        let mut jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: kma::AES_GCM::A256.into(),
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            Json(payload.clone()),
        );
        jwe.header.cek_algorithm.nonce = Some(random_aes_gcm_nonce().unwrap());

        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &EncryptionOptions::None)).compact();

        {
            // Check that new header values are added
            let compact = encrypted_jwe.clone();
            let header: Header<()> = compact.part(0).unwrap();
            assert!(header.cek_algorithm.nonce.is_some());
            assert!(header.cek_algorithm.tag.is_some());

            // Check that the encrypted key part is not empty
            let cek: Vec<u8> = compact.part(1).unwrap();
            assert_eq!(256 / 8, cek.len());
        }

        // Serde test
        let json = not_err!(serde_json::to_string(&encrypted_jwe));
        let deserialized_json: Compact = not_err!(serde_json::from_str(&json));
        assert_eq!(deserialized_json, encrypted_jwe);

        // Decrypt
        let encrypted_jwe: Encrypted<()> = encrypted_jwe.try_into().unwrap();
        let decrypted_jwe = not_err!(encrypted_jwe.decrypt::<Json<String>>(
            &key,
            kma::AES_GCM::A256.into(),
            ContentEncryptionAlgorithm::A256GCM
        ));
        assert_eq!(payload, decrypted_jwe.payload.0);
    }

    #[test]
    fn jwe_a256gcmkw_a256gcm_jws_round_trip() {
        // Construct the JWS
        let claims = crate::ClaimsSet::<()> {
            registered: crate::RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(crate::SingleOrMultiple::Single(not_err!(
                    FromStr::from_str("htts://acme-customer.com")
                ))),
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
        let jws = not_err!(jws.encode(&jws::Secret::Bytes("secret".to_string().into_bytes())));

        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let mut jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: kma::AES_GCM::A256.into(),
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                media_type: Some("JOSE".to_string()),
                content_type: Some("JOSE".to_string()),
                ..Default::default()
            }),
            jws.clone(),
        );
        jwe.header.cek_algorithm.nonce = Some(random_aes_gcm_nonce().unwrap());

        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &EncryptionOptions::None)).compact();

        {
            // Check that new header values are added
            let compact = encrypted_jwe.clone();
            let header: Header<()> = compact.part(0).unwrap();
            assert!(header.cek_algorithm.nonce.is_some());
            assert!(header.cek_algorithm.tag.is_some());

            // Check that the encrypted key part is not empty
            let cek: Vec<u8> = compact.part(1).unwrap();
            assert_eq!(256 / 8, cek.len());
        }

        // Serde test
        let json = not_err!(serde_json::to_string(&encrypted_jwe));
        let deserialized_json: Compact = not_err!(serde_json::from_str(&json));
        assert_eq!(deserialized_json, encrypted_jwe);

        // Decrypt
        let encrypted_jwe: Encrypted<()> = encrypted_jwe.try_into().unwrap();
        let decrypted_jwe = not_err!(encrypted_jwe.decrypt(
            &key,
            kma::AES_GCM::A256.into(),
            ContentEncryptionAlgorithm::A256GCM
        ));
        assert_eq!(jws, decrypted_jwe.payload);
    }

    #[test]
    fn jwe_dir_aes256gcm_jws_round_trip() {
        // Construct the JWS
        let claims = crate::ClaimsSet::<()> {
            registered: crate::RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(crate::SingleOrMultiple::Single(not_err!(
                    FromStr::from_str("htts://acme-customer.com")
                ))),
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
        let jws = not_err!(jws.encode(&jws::Secret::Bytes("secret".to_string().into_bytes())));

        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: kma::Algorithm::DirectSymmetricKey,
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                media_type: Some("JOSE".to_string()),
                content_type: Some("JOSE".to_string()),
                ..Default::default()
            }),
            jws.clone(),
        );
        let options = EncryptionOptions::AES_GCM {
            nonce: random_aes_gcm_nonce().unwrap(),
        };

        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &options)).compact();

        {
            let compact = encrypted_jwe.clone();
            // Check that new header values are empty
            let header: Header<()> = compact.part(0).unwrap();
            assert!(header.cek_algorithm.nonce.is_none());
            assert!(header.cek_algorithm.tag.is_none());

            // Check that the encrypted key part is empty
            let cek: Vec<u8> = compact.part(1).unwrap();
            assert!(cek.is_empty());
        }

        // Serde test
        let json = not_err!(serde_json::to_string(&encrypted_jwe));
        let deserialized_json: Compact = not_err!(serde_json::from_str(&json));
        assert_eq!(deserialized_json, encrypted_jwe);

        // Decrypt
        let encrypted_jwe: Encrypted<()> = encrypted_jwe.try_into().unwrap();
        let decrypted_jwe = not_err!(encrypted_jwe.decrypt(
            &key,
            kma::Algorithm::DirectSymmetricKey,
            ContentEncryptionAlgorithm::A256GCM
        ));
        assert_eq!(jws, decrypted_jwe.payload);
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn decrypt_with_mismatch_cek_algorithm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let mut jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: kma::AES_GCM::A256.into(),
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );
        jwe.header.cek_algorithm.nonce = Some(random_aes_gcm_nonce().unwrap());

        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &EncryptionOptions::None)).compact();

        let encrypted_jwe: Encrypted<()> = encrypted_jwe.try_into().unwrap();
        let _: Decrypted<Vec<u8>, ()> = encrypted_jwe
            .decrypt(
                &key,
                kma::AES_GCM::A128.into(),
                ContentEncryptionAlgorithm::A256GCM,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn decrypt_with_mismatch_enc_algorithm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let mut jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: kma::AES_GCM::A256.into(),
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );
        jwe.header.cek_algorithm.nonce = Some(random_aes_gcm_nonce().unwrap());

        // Encrypt
        let encrypted_jwe = not_err!(jwe.encrypt(&key, &EncryptionOptions::None)).compact();

        let encrypted_jwe: Encrypted<()> = encrypted_jwe.try_into().unwrap();
        let _: Decrypted<Vec<u8>, ()> = encrypted_jwe
            .decrypt(
                &key,
                kma::AES_GCM::A256.into(),
                ContentEncryptionAlgorithm::A128GCM,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "PartsLengthError")]
    fn decrypt_with_incorrect_length() {
        let invalid = Compact::decode("INVALID");
        let _: Encrypted<()> = invalid.try_into().unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_nonce_for_aes256gcmkw() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let mut jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: kma::AES_GCM::A256.into(),
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );
        jwe.header.cek_algorithm.nonce = Some(random_aes_gcm_nonce().unwrap());

        // Encrypt
        let mut encrypted_jwe = not_err!(jwe.encrypt(&key, &EncryptionOptions::None));

        // Modify the JWE
        encrypted_jwe.header.cek_algorithm.nonce = Some(vec![0; 96 / 8]);
        encrypted_jwe.header_base64 = encrypted_jwe.header.to_base64().unwrap().into_owned();

        // Decrypt
        let _ = encrypted_jwe
            .decrypt::<Vec<u8>>(
                &key,
                kma::AES_GCM::A256.into(),
                ContentEncryptionAlgorithm::A256GCM,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_tag_for_aes256gcmkw() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let mut jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: kma::AES_GCM::A256.into(),
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );
        jwe.header.cek_algorithm.nonce = Some(random_aes_gcm_nonce().unwrap());

        // Encrypt
        let mut encrypted_jwe = not_err!(jwe.encrypt(&key, &EncryptionOptions::None));

        // Modify the JWE
        encrypted_jwe.header.cek_algorithm.tag = Some(vec![0; 96 / 8]);
        encrypted_jwe.header_base64 = encrypted_jwe.header.to_base64().unwrap().into_owned();

        // Decrypt
        let _: Decrypted<Vec<u8>, ()> = encrypted_jwe
            .decrypt(
                &key,
                kma::AES_GCM::A256.into(),
                ContentEncryptionAlgorithm::A256GCM,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_tag_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let mut jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: kma::AES_GCM::A256.into(),
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );
        jwe.header.cek_algorithm.nonce = Some(random_aes_gcm_nonce().unwrap());

        // Encrypt
        let mut encrypted_jwe = not_err!(jwe.encrypt(&key, &EncryptionOptions::None));

        // Modify the JWE
        encrypted_jwe.tag = vec![0];

        // Decrypt
        let _: Decrypted<Vec<u8>, ()> = encrypted_jwe
            .decrypt(
                &key,
                kma::AES_GCM::A256.into(),
                ContentEncryptionAlgorithm::A256GCM,
            )
            .unwrap();
    }

    /// This test modifies the header so the tag (aad for the AES GCM) included becomes incorrect
    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_modified_header_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let mut jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: kma::AES_GCM::A256.into(),
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );
        jwe.header.cek_algorithm.nonce = Some(random_aes_gcm_nonce().unwrap());

        // Encrypt
        let mut encrypted_jwe = not_err!(jwe.encrypt(&key, &EncryptionOptions::None));

        // Modify the JWE
        encrypted_jwe.header.registered.media_type = Some("JOSE+JSON".to_string());
        encrypted_jwe.header_base64 = encrypted_jwe.header.to_base64().unwrap().into_owned();

        // Decrypt
        let _: Decrypted<Vec<u8>, ()> = encrypted_jwe
            .decrypt(
                &key,
                kma::AES_GCM::A256.into(),
                ContentEncryptionAlgorithm::A256GCM,
            )
            .unwrap();
    }

    /// This test modifies the encrypted cek
    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_modified_encrypted_cek_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let mut jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: kma::AES_GCM::A256.into(),
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );
        jwe.header.cek_algorithm.nonce = Some(random_aes_gcm_nonce().unwrap());

        // Encrypt
        let mut encrypted_jwe = not_err!(jwe.encrypt(&key, &EncryptionOptions::None));

        // Modify the JWE
        encrypted_jwe.encrypted_cek = vec![0u8; 256 / 8];

        // Decrypt
        let _: Decrypted<Vec<u8>, ()> = encrypted_jwe
            .decrypt(
                &key,
                kma::AES_GCM::A256.into(),
                ContentEncryptionAlgorithm::A256GCM,
            )
            .unwrap();
    }

    /// This test modifies the encrypted payload
    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_modified_encrypted_payload_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let mut jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: kma::AES_GCM::A256.into(),
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );
        jwe.header.cek_algorithm.nonce = Some(random_aes_gcm_nonce().unwrap());

        // Encrypt
        let mut encrypted_jwe = not_err!(jwe.encrypt(&key, &EncryptionOptions::None));

        // Modify the JWE
        encrypted_jwe.encrypted_payload = vec![0u8; 32];

        // Decrypt
        let _: Decrypted<Vec<u8>, ()> = encrypted_jwe
            .decrypt(
                &key,
                kma::AES_GCM::A256.into(),
                ContentEncryptionAlgorithm::A256GCM,
            )
            .unwrap();
    }

    /// This test modifies the nonce
    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_modified_encrypted_nonce_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let mut jwe = Decrypted::new(
            From::from(RegisteredHeader {
                cek_algorithm: kma::AES_GCM::A256.into(),
                enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                ..Default::default()
            }),
            payload.as_bytes().to_vec(),
        );
        jwe.header.cek_algorithm.nonce = Some(random_aes_gcm_nonce().unwrap());

        // Encrypt
        let mut encrypted_jwe = not_err!(jwe.encrypt(&key, &EncryptionOptions::None));

        // Modify the JWE
        encrypted_jwe.iv = vec![0u8; 96 / 8];

        // Decrypt
        let _: Decrypted<Vec<u8>, ()> = encrypted_jwe
            .decrypt(
                &key,
                kma::AES_GCM::A256.into(),
                ContentEncryptionAlgorithm::A256GCM,
            )
            .unwrap();
    }
}
