//! [JSON Web Encryption](https://tools.ietf.org/html/rfc7516)
//!
//! This module contains code to implement JWE, the JOSE standard to encrypt arbitrary payloads.
//! Most commonly, JWE is used to encrypt a JWS payload, which is a signed JWT. For most common use,
//! you will want to look at the  [`Compact`](enum.Compact.html) enum.
use std::borrow::Cow;
use std::fmt::{self, Write};
use std::marker::PhantomData;
use std::str::FromStr;

use base64ct::Encoding;
use serde::de::{self, DeserializeOwned};
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

use crate::errors::{DecodeError, Error, ValidationError};
use crate::jwa::cea::EncryptionResult;
use crate::jwa::{self, cea, kma};
use crate::{FromCompactPart, ToCompactPart};

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
    pub enc_algorithm: cea::Algorithm,

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

impl<KmaHeader, T> FromCompactPart for Header<KmaHeader, T>
where
    KmaHeader: DeserializeOwned,
    T: DeserializeOwned,
{
    fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(serde_json::from_slice(b)?)
    }
}
impl<KmaHeader, T> ToCompactPart for Header<KmaHeader, T>
where
    KmaHeader: Serialize,
    T: Serialize,
{
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

/// A Rust representation of an **encrypted** JWE.
///
/// Can be parsed from a string in it's compact representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted<KMA: kma::KMA, H = ()> {
    header: Header<KMA::Header, H>,
    res: EncryptionResult,
    encrypted_cek: Vec<u8>,
}

impl<KMA, H> FromCompactPart for Encrypted<KMA, H>
where
    KMA: kma::KMA,
    H: DeserializeOwned,
{
    fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        std::str::from_utf8(b)?.parse()
    }
}
impl<KMA, H> ToCompactPart for Encrypted<KMA, H>
where
    KMA: kma::KMA,
{
    fn to_bytes(&self) -> Result<Cow<'_, [u8]>, Error> {
        Ok(self.to_string().into_bytes().into())
    }
}

impl<KMA: kma::KMA, H: Serialize> Serialize for Encrypted<KMA, H> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
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
        let [aad, iv, payload, tag] = self.res.split();

        // safety, we only write ascii base64 into this field
        let s = unsafe { std::str::from_utf8_unchecked(aad) };
        f.write_str(s)?;

        let mut buf = [0; 1024];
        let parts = [&self.encrypted_cek, iv, payload, tag];
        for part in parts {
            f.write_char('.')?;
            for chunk in part.chunks(1024 / 4 * 3) {
                f.write_str(crate::B64::encode(chunk, &mut buf).unwrap())?;
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
        fn decode(output: &mut [u8], input: &str, n: usize) -> Result<usize, base64ct::Error> {
            Ok(crate::B64::decode(input, &mut output[n..])?.len() + n)
        }

        // decodes the JWE using minimal allocations

        let sections: arrayvec::ArrayVec<_, 5> = s.splitn(5, '.').collect();
        let [headerb64, cek, iv, payload, tag] = match sections.into_inner() {
            Ok(s) => s,
            Err(a) => {
                return Err(Error::DecodeError(DecodeError::PartsLengthError {
                    expected: 5,
                    actual: a.len(),
                }))
            }
        };

        let len = headerb64.len() + (iv.len() + payload.len() + tag.len() + 9) * 3 / 4;
        let len = len.max((headerb64.len() + 3) * 3 / 4);
        let mut data = vec![0; len];

        // first, use the alloc space as scratch space for the header deser
        let n = decode(&mut data, headerb64, 0)?;
        let header = serde_json::from_slice(&data[..n])?;

        // then build the compressed encrypted result [aad,iv,payload,tag]
        // where aad=headerb64
        data[..headerb64.len()].copy_from_slice(headerb64.as_bytes());
        let nonce = headerb64.len();
        let p_idx = decode(&mut data, iv, nonce)?;
        let tag_idx = decode(&mut data, payload, p_idx)?;
        let len = decode(&mut data, tag, tag_idx)?;

        data.truncate(len);
        let res = EncryptionResult::from_raw(data, [nonce, p_idx, tag_idx, len]);

        Ok(Self {
            header,
            encrypted_cek: crate::B64::decode_vec(cek)?,
            res,
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
        CEA: jwa::cea::CEA,
        T: FromCompactPart,
    {
        let Self {
            header,
            mut encrypted_cek,
            mut res,
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
        let cek = KMA::unwrap(&mut encrypted_cek, key, header.kma)?;

        // Build encryption result as per steps 14-15
        let payload = CEA::decrypt(cek, &mut res)?;

        // Decompression is not supported at the moment
        if header.registered.compression_algorithm.is_some() {
            return Err(Error::UnsupportedOperation);
        }

        let payload = T::from_bytes(payload)?;

        Ok(Decrypted::new_with_header(payload, header.private))
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
        Self::new_with_header(payload, ())
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
    pub fn new_with_header(payload: T, header: H) -> Self {
        Self { header, payload }
    }
}

impl<T, H> Decrypted<T, H>
where
    T: ToCompactPart,
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
        KMA: jwa::kma::KMA,
    {
        // RFC 7516 Section 5.1 describes the steps involved in encryption.
        // From steps 1 to 8, we will first determine the CEK, and then encrypt the CEK.
        let cek = KMA::generate_key::<CEA>(key);
        let (encrypted_cek, cea_header) = KMA::wrap(&cek, key, key_settings)?;

        // Steps 9 and 10 involves calculating an initialization vector (nonce) for content encryption.
        let iv = CEA::generate_iv();

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
        let encoded_protected_header = crate::B64::encode_string(&header.to_bytes()?);

        // Step 15 involves the actual encryption.
        let res = CEA::encrypt(&cek, &payload, iv, encoded_protected_header.as_bytes())?;

        // Finally create the JWE
        Ok(Encrypted {
            header,
            res,
            encrypted_cek,
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
    use serde_test::{assert_tokens, Token};

    use super::*;
    use crate::jwa::{cea, sign};
    use crate::jwk::OctetKey;
    use crate::test::{assert_serde_json, random_array, random_vec};
    use crate::{jwk, jws, Json};

    pub fn nonce() -> [u8; 12] {
        random_array()
    }

    fn cek_oct_key(len: usize) -> OctetKey {
        jwk::OctetKey::new(random_vec(len))
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
        let key = key.specified.octet_key().unwrap();
        let token: Encrypted<kma::DirectEncryption> = external_token.parse().unwrap();

        let decrypted_jwe = token.decrypt::<Json<String>, cea::A256GCM>(key).unwrap();

        let decrypted_payload = decrypted_jwe.payload;
        assert_eq!(decrypted_payload.0, "Encrypted");
    }

    #[test]
    fn jwe_header_round_trips() {
        let test_value: Header<()> = From::from(RegisteredHeader {
            cek_algorithm: kma::Algorithm::RSA_OAEP,
            enc_algorithm: cea::Algorithm::A256GCM,
            ..Default::default()
        });
        let test_json = r#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#;
        assert_serde_json(&test_value, Some(test_json));

        let test_value: Header<()> = From::from(RegisteredHeader {
            cek_algorithm: kma::Algorithm::RSA1_5,
            enc_algorithm: cea::Algorithm::A128CBC_HS256,
            ..Default::default()
        });
        let test_json = r#"{"alg":"RSA1_5","enc":"A128CBC-HS256"}"#;
        assert_serde_json(&test_value, Some(test_json));

        let test_value: Header<()> = From::from(RegisteredHeader {
            cek_algorithm: kma::Algorithm::A128KW,
            enc_algorithm: cea::Algorithm::A128CBC_HS256,
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
                enc_algorithm: cea::Algorithm::A256GCM,
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
        let cek_nonce = nonce();

        // Encrypt
        let encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Check that the encrypted key part is not empty
        assert_eq!(256 / 8, encrypted_jwe.encrypted_cek.len());

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
                issuer: Some("https://www.acme.com".into()),
                subject: Some("John Doe".into()),
                audience: Some("htts://acme-customer.com".into()),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: Default::default(),
        };

        let key = OctetKey::new("secret".to_string().into_bytes());
        let jws = jws::Verified::new(claims);
        let jws = jws.encode::<sign::HS256>(&key).unwrap();

        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let jwe = Decrypted::new(jws.clone());
        let cek_nonce = nonce();

        // Encrypt
        let encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Check that the encrypted key part is not empty
        assert_eq!(256 / 8, encrypted_jwe.encrypted_cek.len());

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
                issuer: Some("https://www.acme.com".into()),
                subject: Some("John Doe".into()),
                audience: Some("htts://acme-customer.com".into()),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: Default::default(),
        };

        let key = OctetKey::new("secret".to_string().into_bytes());
        let jws = jws::Verified::new(claims);
        let jws = jws.encode::<sign::HS256>(&key).unwrap();

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
        let cek_nonce = nonce();

        // Encrypt
        let encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // reparse it as a A128GCMKW jwe
        let encrypted_jwe: Encrypted<kma::A128GCMKW> = encrypted_jwe.to_string().parse().unwrap();

        encrypted_jwe
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
        let cek_nonce = nonce();

        // Encrypt
        let encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        encrypted_jwe
            .decrypt::<Vec<u8>, cea::A128GCM>(&key)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "PartsLengthError")]
    fn decrypt_with_incorrect_length() {
        let _token: Encrypted<kma::DirectEncryption> = "INVALID".parse().unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_nonce_for_aes256gcmkw() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(payload.as_bytes().to_vec());
        let cek_nonce = nonce();

        // Encrypt
        let mut encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Modify the JWE
        let [_, iv, payload, tag] = encrypted_jwe.res.split();
        encrypted_jwe.header.kma.iv = [0; 96 / 8];
        encrypted_jwe.res = EncryptionResult::from([
            crate::B64::encode_string(&encrypted_jwe.header.to_bytes().unwrap()).as_bytes(),
            iv,
            payload,
            tag,
        ]);

        // Decrypt
        encrypted_jwe
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
        let cek_nonce = nonce();

        // Encrypt
        let mut encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Modify the JWE
        let [_, iv, payload, tag] = encrypted_jwe.res.split();
        encrypted_jwe.header.kma.tag = [0; 16];
        encrypted_jwe.res = EncryptionResult::from([
            crate::B64::encode_string(&encrypted_jwe.header.to_bytes().unwrap()).as_bytes(),
            iv,
            payload,
            tag,
        ]);

        // Decrypt
        let _token: Decrypted<Vec<u8>, ()> =
            encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnspecifiedCryptographicError")]
    fn invalid_tag_for_aes256gcm() {
        // Construct the encryption key
        let key = cek_oct_key(256 / 8);

        // Construct the JWE
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = Decrypted::new(payload.as_bytes().to_vec());
        let cek_nonce = nonce();

        // Encrypt
        let mut encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Modify the JWE
        let [header, iv, payload, _] = encrypted_jwe.res.split();
        encrypted_jwe.res = EncryptionResult::from([header, iv, payload, &[0]]);

        // Decrypt
        let _token: Decrypted<Vec<u8>, ()> =
            encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
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
        let cek_nonce = nonce();

        // Encrypt
        let mut encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Modify the JWE
        let [_, iv, payload, tag] = encrypted_jwe.res.split();
        encrypted_jwe.header.registered.media_type = Some("JOSE+JSON".to_string());
        encrypted_jwe.res = EncryptionResult::from([
            crate::B64::encode_string(&encrypted_jwe.header.to_bytes().unwrap()).as_bytes(),
            iv,
            payload,
            tag,
        ]);

        // Decrypt
        let _token: Decrypted<Vec<u8>, ()> =
            encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
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
        let cek_nonce = nonce();

        // Encrypt
        let mut encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Modify the JWE
        encrypted_jwe.encrypted_cek = vec![0u8; 256 / 8];

        // Decrypt
        let _token: Decrypted<Vec<u8>, ()> =
            encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
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
        let cek_nonce = nonce();

        // Encrypt
        let mut encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Modify the JWE
        let [header, iv, _, tag] = encrypted_jwe.res.split();
        encrypted_jwe.res = EncryptionResult::from([header, iv, &[0; 32], tag]);

        // Decrypt
        let _token: Decrypted<Vec<u8>, ()> =
            encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
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
        let cek_nonce = nonce();

        // Encrypt
        let mut encrypted_jwe = jwe
            .encrypt::<cea::A256GCM, kma::A256GCMKW>(&key, cek_nonce)
            .unwrap();

        // Modify the JWE
        let [header, _, payload, tag] = encrypted_jwe.res.split();
        encrypted_jwe.res = EncryptionResult::from([header, &[0; 96 / 8], payload, tag]);

        // Decrypt
        let _token: Decrypted<Vec<u8>, ()> =
            encrypted_jwe.decrypt::<_, cea::A256GCM>(&key).unwrap();
    }
}
