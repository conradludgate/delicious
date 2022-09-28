use std::borrow::Cow;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::errors::{Error, ValidationError};
use crate::jwa::{Algorithm, SignatureAlgorithm};
use crate::jwk::{AlgorithmParameters, JWKSet};
use crate::{CompactPart, Json};

use super::{Header, Secret};

/// Rust representation of a JWS
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Encoded<T, H = ()> {
    header: Header<H>,
    payload: T,
    payload_base64: String,
    signature: Vec<u8>,
}

impl<T, H> CompactPart for Encoded<T, H>
where
    T: CompactPart,
    H: Serialize + DeserializeOwned,
{
    fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        std::str::from_utf8(b)?.parse()
    }

    fn to_bytes(&self) -> Result<Cow<'_, [u8]>, Error> {
        Ok(self.to_string().into_bytes().into())
    }
}

impl<T, H> Serialize for Encoded<T, H> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de, T: CompactPart, H: DeserializeOwned> serde::Deserialize<'de> for Encoded<T, H> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EncodedVisitor<T, H>(PhantomData<(T, H)>);

        impl<'de, T: CompactPart, H: DeserializeOwned> serde::de::Visitor<'de> for EncodedVisitor<T, H> {
            type Value = Encoded<T, H>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string containing a compact JOSE representation of a JWS")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(EncodedVisitor(PhantomData))
    }
}

impl<T, H> fmt::Display for Encoded<T, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.payload_base64)?;
        f.write_str(".")?;
        let mut buf = [0; 1024];
        for chunk in self.signature.chunks(1024 / 4 * 3) {
            let n = base64::encode_config_slice(chunk, base64::URL_SAFE_NO_PAD, &mut buf);
            let s = unsafe { std::str::from_utf8_unchecked(&buf[..n]) };
            f.write_str(s)?
        }
        Ok(())
    }
}

impl<T, H> FromStr for Encoded<T, H>
where
    T: CompactPart,
    H: DeserializeOwned,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (payload_base64, sig) = s.rsplit_once('.').ok_or(Error::DecodeError(
            crate::errors::DecodeError::PartsLengthError {
                expected: 3,
                actual: 1,
            },
        ))?;

        let signature = base64::decode_config(sig, base64::URL_SAFE_NO_PAD)?;

        let (header, payload) = payload_base64.split_once('.').ok_or(Error::DecodeError(
            crate::errors::DecodeError::PartsLengthError {
                expected: 3,
                actual: 2,
            },
        ))?;

        let header = base64::decode_config(header, base64::URL_SAFE_NO_PAD)?;
        let header = serde_json::from_slice(&header)?;
        let payload = T::from_base64(payload)?;

        Ok(Self {
            header,
            payload,
            payload_base64: payload_base64.to_owned(),
            signature,
        })
    }
}

/// Rust representation of a JWS
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decoded<T, H = ()> {
    /// Embedded header
    pub header: Header<H>,
    /// Payload, usually a claims set
    pub payload: T,
}

impl<T, H> Decoded<T, H>
where
    T: Serialize + DeserializeOwned,
    H: Serialize + DeserializeOwned,
{
    /// Encode the JWT passed and sign the payload using the algorithm from the header and the secret
    /// The secret is dependent on the signing algorithm
    pub fn encode_json(self, secret: &Secret) -> Result<Encoded<Json<T>, H>, Error> {
        let Self { header, payload } = self;
        Decoded {
            header,
            payload: Json(payload),
        }
        .encode(secret)
    }
    /// Decode a token into the JWT struct and verify its signature using the concrete Secret
    /// If the token or its signature is invalid, it will return an error
    pub fn decode_json(
        encoded: Encoded<Json<T>, H>,
        secret: &Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self, Error> {
        let Decoded { header, payload } = Decoded::decode(encoded, secret, algorithm)?;
        Ok(Self {
            header,
            payload: payload.0,
        })
    }
}

impl<T, H> Decoded<T, H>
where
    T: CompactPart,
    H: Serialize + DeserializeOwned,
{
    /// New decoded JWT
    pub fn new(header: Header<H>, payload: T) -> Self {
        Self { header, payload }
    }

    /// Encode the JWT passed and sign the payload using the algorithm from the header and the secret
    /// The secret is dependent on the signing algorithm
    pub fn encode(self, secret: &Secret) -> Result<Encoded<T, H>, Error> {
        let Self { header, payload } = self;
        let mut payload_base64 = header.to_base64()?.into_owned();
        payload_base64.push('.');
        payload_base64.push_str(&payload.to_base64()?);
        let signature = header
            .registered
            .algorithm
            .sign(payload_base64.as_bytes(), secret)?;
        Ok(Encoded {
            payload_base64,
            header,
            payload,
            signature,
        })
    }

    /// Decode a token into the JWT struct and verify its signature using the concrete Secret
    /// If the token or its signature is invalid, it will return an error
    pub fn decode(
        encoded: Encoded<T, H>,
        secret: &Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self, Error> {
        let Encoded {
            header,
            payload,
            payload_base64,
            signature,
        } = encoded;

        if header.registered.algorithm != algorithm {
            Err(ValidationError::WrongAlgorithmHeader)?;
        }

        algorithm
            .verify(signature.as_ref(), payload_base64.as_bytes(), secret)
            .map_err(|_| ValidationError::InvalidSignature)?;

        Ok(Self::new(header, payload))
    }

    /// Decode a token into the JWT struct and verify its signature using a JWKS
    ///
    /// If the JWK does not contain an optional algorithm parameter, you will have to specify
    /// the expected algorithm or an error will be returned.
    ///
    /// If the JWK specifies an algorithm and you provide an expected algorithm,
    /// both will be checked for equality. If they do not match, an error will be returned.
    ///
    /// If the token or its signature is invalid, it will return an error
    pub fn decode_with_jwks<J>(
        encoded: Encoded<T, H>,
        jwks: &JWKSet<J>,
        expected_algorithm: Option<SignatureAlgorithm>,
    ) -> Result<Self, Error> {
        let Encoded {
            header,
            payload,
            payload_base64,
            signature,
        } = encoded;

        let key_id = header
            .registered
            .key_id
            .as_ref()
            .ok_or(ValidationError::KidMissing)?;
        let jwk = jwks.find(key_id).ok_or(ValidationError::KeyNotFound)?;

        let algorithm = match jwk.specified.common.algorithm {
            Some(jwk_alg) => {
                let algorithm = match jwk_alg {
                    Algorithm::Signature(algorithm) => algorithm,
                    _ => Err(ValidationError::UnsupportedKeyAlgorithm)?,
                };

                if header.registered.algorithm != algorithm {
                    Err(ValidationError::WrongAlgorithmHeader)?;
                }

                if let Some(expected_algorithm) = expected_algorithm {
                    if expected_algorithm != algorithm {
                        Err(ValidationError::WrongAlgorithmHeader)?;
                    }
                }

                algorithm
            }
            None => match expected_algorithm {
                Some(expected_algorithm) => {
                    if expected_algorithm != header.registered.algorithm {
                        Err(ValidationError::WrongAlgorithmHeader)?;
                    }
                    expected_algorithm
                }
                None => Err(ValidationError::MissingAlgorithm)?,
            },
        };

        let secret = match &jwk.specified.algorithm {
            AlgorithmParameters::RSA(rsa) => rsa.jws_public_key_secret(),
            AlgorithmParameters::OctetKey(oct) => Secret::Bytes(oct.value.clone()),
            _ => Err(ValidationError::UnsupportedKeyAlgorithm)?,
        };

        algorithm
            .verify(signature.as_ref(), payload_base64.as_bytes(), &secret)
            .map_err(|_| ValidationError::InvalidSignature)?;

        Ok(Self::new(header, payload))
    }
}

/// Convenience implementation for a Compact that contains a `ClaimsSet`
impl<P, H> Decoded<crate::ClaimsSet<P>, H>
where
    crate::ClaimsSet<P>: Serialize + DeserializeOwned,
    H: Serialize + DeserializeOwned,
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
    use std::borrow::Cow;
    use std::str::{self, FromStr};

    use serde::{Deserialize, Serialize};

    use super::{Decoded, Encoded, Header, Secret, SignatureAlgorithm};
    use crate::errors::Error;
    use crate::jwk::JWKSet;
    use crate::jws::RegisteredHeader;
    use crate::{ClaimsSet, CompactPart, RegisteredClaims, SingleOrMultiple};

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct PrivateClaims {
        company: String,
        department: String,
    }

    impl CompactPart for PrivateClaims {
        fn from_bytes(b: &[u8]) -> Result<Self, Error> {
            Ok(serde_json::from_slice(b)?)
        }

        fn to_bytes(&self) -> Result<Cow<'_, [u8]>, Error> {
            Ok(serde_json::to_vec(&self)?.into())
        }
    }

    // impl CompactJson for PrivateClaims {}

    // HS256 key - "secret"
    static HS256_PAYLOAD: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
        eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1ZCI6Imh0dHBzOi8vYWNtZ\
        S1jdXN0b21lci5jb20vIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2x\
        lYW5pbmcifQ.VFCl2un1Kc17odzOe2Ehf4DVrWddu3U4Ux3GFpOZHtc";

    #[test]
    fn compact_jws_round_trip_none() {
        let expected_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.\
            eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1ZCI6Imh0dHBzOi8vY\
            WNtZS1jdXN0b21lci5jb20vIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2l\
            sZXQgQ2xlYW5pbmcifQ.";

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "https://acme-customer.com/"
                )))),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let expected_jwt = Decoded::new(
            From::from(RegisteredHeader {
                algorithm: SignatureAlgorithm::None,
                ..Default::default()
            }),
            expected_claims.clone(),
        );
        let token = not_err!(expected_jwt.encode(&Secret::None));
        assert_eq!(expected_token, token.to_string());

        let biscuit: Decoded<ClaimsSet<PrivateClaims>, ()> = not_err!(Decoded::decode(
            token,
            &Secret::None,
            SignatureAlgorithm::None
        ));
        assert_eq!(expected_claims, biscuit.payload);
    }

    #[test]
    fn compact_jws_round_trip_hs256() {
        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "https://acme-customer.com/"
                )))),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let expected_jwt = Decoded::new(
            From::from(RegisteredHeader {
                algorithm: SignatureAlgorithm::HS256,
                ..Default::default()
            }),
            expected_claims.clone(),
        );
        let token =
            not_err!(expected_jwt.encode(&Secret::Bytes("secret".to_string().into_bytes())));
        assert_eq!(HS256_PAYLOAD, token.to_string());

        let biscuit: Decoded<ClaimsSet<PrivateClaims>, ()> = not_err!(Decoded::decode(
            token,
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256
        ));
        assert_eq!(expected_claims, biscuit.payload);
    }

    #[test]
    fn compact_jws_round_trip_rs256() {
        let expected_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
                              eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1Z\
                              CI6Imh0dHBzOi8vYWNtZS1jdXN0b21lci5jb20vIiwibmJmIjoxMjM0LCJjb21wYW55Ij\
                              oiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
                              Gat3NBUTaCyvroil66U0nId4-l6VqbtJYIsM9wRbWo45oYoN-NxYIyl8M-9AlEPseg-4SIuo-A-jccJOWGeWWwy-E\
                              en_92wg18II58luHz7vAyclw1maJBKHmuj8f2wE_Ky8ir3iTpTGkJQ3IUU9SuU9Fkvajm4jgWUtRPpjHm_IqyxV8N\
                              kHNyN0p5CqeuRC8sZkOSFkm9b0WnWYRVls1QOjBnN9w9zW9wg9DGwj10pqg8hQ5sy-C3J-9q1zJgGDXInkhPLjitO\
                              9wzWg4yfVt-CJNiHsJT7RY_EN2VmbG8UOjHp8xUPpfqUKyoQttKaQkJHdjP_b47LO4ZKI4UivlA";

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "https://acme-customer.com/"
                )))),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };
        let private_key =
            Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();

        let expected_jwt = Decoded::new(
            From::from(RegisteredHeader {
                algorithm: SignatureAlgorithm::RS256,
                ..Default::default()
            }),
            expected_claims.clone(),
        );
        let token = not_err!(expected_jwt.encode(&private_key));
        assert_eq!(expected_token, token.to_string());

        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let biscuit: Decoded<_, ()> = not_err!(Decoded::decode(
            token,
            &public_key,
            SignatureAlgorithm::RS256
        ));
        assert_eq!(expected_claims, biscuit.payload);
    }

    #[test]
    fn compact_jws_verify_es256() {
        // This is a ECDSA Public key in `SubjectPublicKey` form.
        // Conversion is not available in `ring` yet.
        // See https://github.com/lawliet89/biscuit/issues/71#issuecomment-296445140 for a
        // way to retrieve it from `SubjectPublicKeyInfo`.
        let public_key =
            "043727F96AAD416887DD75CC2E333C3D8E06DCDF968B6024579449A2B802EFC891F638C75\
             1CF687E6FF9A280E11B7036585E60CA32BB469C3E57998A289E0860A6";
        let jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.\
                   eyJ0b2tlbl90eXBlIjoic2VydmljZSIsImlhdCI6MTQ5MjkzODU4OH0.\
                   do_XppIOFthPWlTXL95CIBfgRdyAxbcIsUfM0YxMjCjqvp4ehHFA3I-JasABKzC8CAy4ndhCHsZdpAtK\
                   kqZMEA";
        let signing_secret = Secret::PublicKey(hex::decode(public_key.as_bytes()).unwrap());

        let token = Encoded::from_str(jwt).unwrap();
        let _ = not_err!(Decoded::<ClaimsSet<serde_json::Value>, ()>::decode(
            token,
            &signing_secret,
            SignatureAlgorithm::ES256
        ));
    }

    #[test]
    fn compact_jws_encode_with_additional_header_fields() {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct CustomHeader {
            something: String,
        }

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "https://acme-customer.com/"
                )))),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let header = Header {
            registered: Default::default(),
            private: CustomHeader {
                something: "foobar".to_string(),
            },
        };

        let expected_jwt = Decoded::new(header.clone(), expected_claims);
        let token =
            not_err!(expected_jwt.encode(&Secret::Bytes("secret".to_string().into_bytes())));
        let biscuit: Decoded<ClaimsSet<PrivateClaims>, CustomHeader> = not_err!(Decoded::decode(
            token,
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256
        ));
        assert_eq!(header, biscuit.header);
    }

    #[test]
    #[should_panic(expected = "PartsLengthError { expected: 3, actual: 1 }")]
    fn compact_jws_decode_token_missing_parts() {
        let token = Encoded::from_str("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9").unwrap();
        let claims = Decoded::<PrivateClaims, ()>::decode(
            token,
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256,
        );
        let _ = claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn compact_jws_decode_token_invalid_signature_hs256() {
        let token = Encoded::from_str(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJkZXBhcnRtZW50IjoiQ3J5cHRvIn0.\
             pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI",
        )
        .unwrap();
        let claims = Decoded::<PrivateClaims, ()>::decode(
            token,
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256,
        );
        let _ = claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn compact_jws_decode_token_invalid_signature_rs256() {
        let token = Encoded::from_str(
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJkZXBhcnRtZW50IjoiQ3J5cHRvIn0.\
             pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI",
        )
        .unwrap();
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let claims =
            Decoded::<PrivateClaims, ()>::decode(token, &public_key, SignatureAlgorithm::RS256);
        let _ = claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_token_wrong_algorithm() {
        let token = Encoded::from_str(
            "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.\
             eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJkZXBhcnRtZW50IjoiQ3J5cHRvIn0.\
             pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI",
        )
        .unwrap();
        let claims = Decoded::<PrivateClaims, ()>::decode(
            token,
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256,
        );
        let _ = claims.unwrap();
    }

    #[test]
    fn compact_jws_round_trip_hs256_for_bytes_payload() {
        let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IlJhbmRvbSBieXRlcyJ9.\
            eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
            E5ahoj_gMO8WZzSUhquWuBkPLGZm18zaLbyHUQA7TIs";
        let payload: Vec<u8> = vec![
            123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120,
            112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116,
            112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95,
            114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
        ];

        let expected_jwt = Decoded::new(
            From::from(RegisteredHeader {
                algorithm: SignatureAlgorithm::HS256,
                content_type: Some("Random bytes".to_string()),
                ..Default::default()
            }),
            payload.clone(),
        );
        let token =
            not_err!(expected_jwt.encode(&Secret::Bytes("secret".to_string().into_bytes())));
        assert_eq!(expected_token, token.to_string());

        let biscuit: Decoded<Vec<u8>, ()> = not_err!(Decoded::decode(
            token,
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256
        ));
        assert_eq!(payload, biscuit.payload);
    }

    #[test]
    fn compact_jws_decode_with_jwks_shared_secret() {
        let token = Encoded::from_str(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        )
        .unwrap();

        let jwks: JWKSet<()> = serde_json::from_str(
            r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ =
            Decoded::<PrivateClaims, ()>::decode_with_jwks(token, &jwks, None).expect("to succeed");
    }

    /// JWK has algorithm and user provided a matching expected algorithm
    #[test]
    fn compact_jws_decode_with_jwks_shared_secret_matching_alg() {
        let token = Encoded::from_str(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        )
        .unwrap();

        let jwks: JWKSet<()> = serde_json::from_str(
            r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = Decoded::<PrivateClaims, ()>::decode_with_jwks(
            token,
            &jwks,
            Some(SignatureAlgorithm::HS256),
        )
        .expect("to succeed");
    }

    /// JWK has algorithm and user provided a non-matching expected algorithm
    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_with_jwks_shared_secret_mismatched_alg() {
        let token = Encoded::from_str(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        )
        .unwrap();

        let jwks: JWKSet<()> = serde_json::from_str(
            r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = Decoded::<PrivateClaims, ()>::decode_with_jwks(
            token,
            &jwks,
            Some(SignatureAlgorithm::RS256),
        )
        .unwrap();
    }

    /// JWK has no algorithm and user provided a header matching expected algorithm
    #[test]
    fn compact_jws_decode_with_jwks_without_alg() {
        let token = Encoded::from_str(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        )
        .unwrap();

        let jwks: JWKSet<()> = serde_json::from_str(
            r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = Decoded::<PrivateClaims, ()>::decode_with_jwks(
            token,
            &jwks,
            Some(SignatureAlgorithm::HS256),
        )
        .unwrap();
    }

    /// JWK has no algorithm and user provided a header not-matching expected algorithm
    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_with_jwks_without_alg_non_matching() {
        let token = Encoded::from_str(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        )
        .unwrap();

        let jwks: JWKSet<()> = serde_json::from_str(
            r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = Decoded::<PrivateClaims, ()>::decode_with_jwks(
            token,
            &jwks,
            Some(SignatureAlgorithm::RS256),
        )
        .unwrap();
    }

    /// JWK has no algorithm and user did not provide any expected algorithm
    #[test]
    #[should_panic(expected = "MissingAlgorithm")]
    fn compact_jws_decode_with_jwks_missing_alg() {
        let token = Encoded::from_str(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        )
        .unwrap();

        let jwks: JWKSet<()> = serde_json::from_str(
            r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = Decoded::<PrivateClaims, ()>::decode_with_jwks(token, &jwks, None).unwrap();
    }

    #[test]
    fn compact_jws_decode_with_jwks_rsa() {
        let token = Encoded::from_str(
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             MImpi6zezEy0PE5uHU7hM1I0VaNPQx4EAYjEnq2v4gyypmfgKqzrSntSACHZvPsLHDN\
             Ui8PGBM13NcF5IxhybHRM_LVMlMK2rlmQQR7NYueV1psfdSh6fGcYoDxuiZnzybpSxP\
             5Fy8wGe-BgoL5EIPzzhfQBZagzliztLt8RarXHbXnK_KxN1GE5_q5V_ZvjpNr3FExuC\
             cKSvjhlkWR__CmTpv4FWZDkWXJgABLSd0Fe1soUNXMNaqzeTH-xSIYMv06Jckfky6Ds\
             OKcqWyA5QGNScRkSh4fu4jkIiPlituJhFi3hYgIfGTGQMDt2TsiaUCZdfyLhipGwHzmMijeHiQ",
        )
        .unwrap();

        let jwks: JWKSet<()> = serde_json::from_str(
            r#"{
            "keys": [
                        {
                            "kty": "RSA",
                            "e": "AQAB",
                            "use": "sig",
                            "kid": "key0",
                            "alg": "RS256",
                            "n": "rx7xQsC4XuzCW1YZwm3JUftsScV3v82VmuuIcmUOBGyLpeChfHwwr61UZOVL6yiFSIoGlS1KbVkyZ5xf8FCQGdRuAYvx2sH4E0D9gOdjAauXIx7ADbG5wfTHqiyYcWezovzdXZb4F7HCaBkaKhtg8FTkTozQz5m6stzcFatcSUZpNM6lCSGoi0kFfucEAV2cNoWUaW1WnYyGB2sxupSIako9updQIHfAqiDSbawO8uBymNjiQJS3evImjLcJajAYzrmK1biSu5uJuw3RReYef3QUvLY9o2T6LV3QiIWi3MeBktjhwAvCKzcOeU34py946AJm6USXkwit_hlFx5DzgQ"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ =
            Decoded::<PrivateClaims, ()>::decode_with_jwks(token, &jwks, None).expect("to succeed");
    }

    #[test]
    #[should_panic(expected = "PartsLengthError { expected: 3, actual: 2 }")]
    fn compact_jws_decode_with_jwks_missing_parts() {
        let token = Encoded::from_str(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ",
        )
        .unwrap();

        let jwks: JWKSet<()> = serde_json::from_str(
            r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = Decoded::<PrivateClaims, ()>::decode_with_jwks(token, &jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_with_jwks_wrong_algorithm() {
        let token = Encoded::from_str(
            "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        )
        .unwrap();

        let jwks: JWKSet<()> = serde_json::from_str(
            r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = Decoded::<PrivateClaims, ()>::decode_with_jwks(token, &jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "KeyNotFound")]
    fn compact_jws_decode_with_jwks_key_not_found() {
        let token = Encoded::from_str(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        )
        .unwrap();

        let jwks: JWKSet<()> = serde_json::from_str(
            r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "keyX",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = Decoded::<PrivateClaims, ()>::decode_with_jwks(token, &jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "KidMissing")]
    fn compact_jws_decode_with_jwks_kid_missing() {
        let token = Encoded::from_str(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             QhdrScTpNXF2d0RbG_UTWu2gPKZfzANj6XC4uh-wOoU",
        )
        .unwrap();

        let jwks: JWKSet<()> = serde_json::from_str(
            r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = Decoded::<PrivateClaims, ()>::decode_with_jwks(token, &jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnsupportedKeyAlgorithm")]
    fn compact_jws_decode_with_jwks_algorithm_not_supported() {
        let token = Encoded::from_str(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        )
        .unwrap();

        let jwks: JWKSet<()> = serde_json::from_str(
            r#"{
            "keys": [
                        {
                            "kty": "oct",
                            "use": "sig",
                            "kid": "key0",
                            "k": "-clnNQnBupZt23N8McUcZytLhan9OmjlJXmqS7daoeY",
                            "alg": "A128CBC-HS256"
                        }
            ]
        }"#,
        )
        .unwrap();

        let _ = Decoded::<PrivateClaims, ()>::decode_with_jwks(token, &jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnsupportedKeyAlgorithm")]
    fn compact_jws_decode_with_jwks_key_type_not_supported() {
        let token = Encoded::from_str(
            "eyJhbGciOiAiRVMyNTYiLCJ0eXAiOiAiSldUIiwia2lkIjogImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        )
        .unwrap();

        let jwks: JWKSet<()> = serde_json::from_str(
            r#"{
            "keys": [
                {
                    "kty": "EC",
                    "d": "oEMWfLRjrJdYa8OdfNz2_X2UrTet1Lnu2fIdlq7-Qd8",
                    "use": "sig",
                    "crv": "P-256",
                    "kid": "key0",
                    "x": "ZnXv09eyorTiF0AdN6HW-kltr0tt0GbgmD2_VGGlapI",
                    "y": "vERyG9Enhy8pEZ6V_pomH8aGjO7cINteCmnV5B9y0f0",
                    "alg": "ES256"
                }
            ]
        }"#,
        )
        .unwrap();

        let _ = Decoded::<PrivateClaims, ()>::decode_with_jwks(token, &jwks, None).unwrap();
    }
}
