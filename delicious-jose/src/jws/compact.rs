use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::errors::{Error, ValidationError};
use crate::jwa::{Algorithm, SignatureAlgorithm};
use crate::jwk::{AlgorithmParameters, JWKSet};

use super::{Header, Secret};

/// Rust representation of a JWS
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decoded<T, H> {
    /// Embedded header
    header: Header<H>,
    /// Payload, usually a claims set
    payload: T,
}

impl<T, H> Decoded<T, H>
where
    T: Serialize + DeserializeOwned,
    H: Serialize + DeserializeOwned,
{
    /// New decoded JWT
    pub fn new(header: Header<H>, payload: T) -> Self {
        Self { header, payload }
    }

    /// Encode the JWT passed and sign the payload using the algorithm from the header and the secret
    /// The secret is dependent on the signing algorithm
    pub fn encode(&self, secret: &Secret) -> Result<crate::Compact, Error> {
        let mut compact = crate::Compact::new();
        compact.push(&self.header)?;
        compact.push(&self.payload)?;
        let encoded_payload = compact.as_str();
        let signature = &self
            .header
            .registered
            .algorithm
            .sign(encoded_payload.as_bytes(), secret)?;
        compact.push_bytes(signature);
        Ok(compact)
    }

    /// Decode a token into the JWT struct and verify its signature using the concrete Secret
    /// If the token or its signature is invalid, it will return an error
    pub fn decode(
        encoded: &crate::Compact,
        secret: &Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self, Error> {
        let (payload, signature) = encoded.parse_triple()?;
        algorithm
            .verify(signature.as_ref(), payload.as_ref(), secret)
            .map_err(|_| ValidationError::InvalidSignature)?;

        let header: Header<H> = encoded.deser_part(0)?;
        if header.registered.algorithm != algorithm {
            Err(ValidationError::WrongAlgorithmHeader)?;
        }
        let decoded_claims: T = encoded.deser_part(1)?;

        Ok(Self::new(header, decoded_claims))
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
        encoded: &crate::Compact,
        jwks: &JWKSet<J>,
        expected_algorithm: Option<SignatureAlgorithm>,
    ) -> Result<Self, Error> {
        let (payload, signature) = encoded.parse_triple()?;
        let header: Header<H> = encoded.deser_part(0)?;
        let key_id = header
            .registered
            .key_id
            .as_ref()
            .ok_or(ValidationError::KidMissing)?;
        let jwk = jwks.find(key_id).ok_or(ValidationError::KeyNotFound)?;

        let algorithm = match jwk.common.algorithm {
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

        let secret = match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => rsa.jws_public_key_secret(),
            AlgorithmParameters::OctetKey(oct) => Secret::Bytes(oct.value.clone()),
            _ => Err(ValidationError::UnsupportedKeyAlgorithm)?,
        };

        algorithm
            .verify(signature.as_ref(), payload.as_ref(), &secret)
            .map_err(|_| ValidationError::InvalidSignature)?;

        let decoded_claims: T = encoded.deser_part(1)?;

        Ok(Self::new(header, decoded_claims))
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
    use std::str::{self, FromStr};

    use serde::{Deserialize, Serialize};

    use super::{Decoded, Header, Secret, SignatureAlgorithm};
    use crate::jwk::JWKSet;
    use crate::jws::RegisteredHeader;
    use crate::{ClaimsSet, Compact, Empty, RegisteredClaims, SingleOrMultiple};

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct PrivateClaims {
        company: String,
        department: String,
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

        let biscuit: Decoded<ClaimsSet<PrivateClaims>, Empty> = not_err!(Decoded::decode(
            &token,
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

        let biscuit: Decoded<ClaimsSet<PrivateClaims>, Empty> = not_err!(Decoded::decode(
            &token,
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
        let biscuit: Decoded<_, Empty> = not_err!(Decoded::decode(
            &token,
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

        let token = Compact::decode(jwt);
        let _ = not_err!(Decoded::<ClaimsSet<serde_json::Value>, Empty>::decode(
            &token,
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
            &token,
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256
        ));
        assert_eq!(header, biscuit.header);
    }

    #[test]
    #[should_panic(expected = "PartsLengthError { expected: 3, actual: 1 }")]
    fn compact_jws_decode_token_missing_parts() {
        let token = Compact::decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        let claims = Decoded::<PrivateClaims, Empty>::decode(
            &token,
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256,
        );
        let _ = claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn compact_jws_decode_token_invalid_signature_hs256() {
        let token = Compact::decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
             pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI",
        );
        let claims = Decoded::<PrivateClaims, Empty>::decode(
            &token,
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256,
        );
        let _ = claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn compact_jws_decode_token_invalid_signature_rs256() {
        let token = Compact::decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
             pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI",
        );
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let claims =
            Decoded::<PrivateClaims, Empty>::decode(&token, &public_key, SignatureAlgorithm::RS256);
        let _ = claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_token_wrong_algorithm() {
        let token = Compact::decode(
            "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.\
             eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.\
             pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI",
        );
        let claims = Decoded::<PrivateClaims, Empty>::decode(
            &token,
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256,
        );
        let _ = claims.unwrap();
    }

    #[test]
    fn compact_jws_round_trip_hs256_for_bytes_payload() {
        let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IlJhbmRvbSBieXRlcyJ9.\
            WzEyMywzNCwxMDUsMTE1LDExNSwzNCw1OCwzNCwxMDYsMTExLDEwMSwzNCw0NCwxMywxMCwzMiwzNCwxMDEs\
            MTIwLDExMiwzNCw1OCw0OSw1MSw0OCw0OCw1Niw0OSw1Nyw1MSw1Niw0OCw0NCwxMywxMCwzMiwzNCwxMDQs\
            MTE2LDExNiwxMTIsNTgsNDcsNDcsMTAxLDEyMCw5NywxMDksMTEyLDEwOCwxMDEsNDYsOTksMTExLDEwOSw0\
            NywxMDUsMTE1LDk1LDExNCwxMTEsMTExLDExNiwzNCw1OCwxMTYsMTE0LDExNywxMDEsMTI1XQ.\
            Dkgt7e34IW2Hxs-k2CLvKxB0szXgRbnHnr5gr1H4-Yg";
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

        let biscuit: Decoded<Vec<u8>, Empty> = not_err!(Decoded::decode(
            &token,
            &Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256
        ));
        assert_eq!(payload, biscuit.payload);
    }

    #[test]
    fn compact_jws_decode_with_jwks_shared_secret() {
        let token = Compact::decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
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

        let _ = Decoded::<PrivateClaims, Empty>::decode_with_jwks(&token, &jwks, None)
            .expect("to succeed");
    }

    /// JWK has algorithm and user provided a matching expected algorithm
    #[test]
    fn compact_jws_decode_with_jwks_shared_secret_matching_alg() {
        let token = Compact::decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
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

        let _ = Decoded::<PrivateClaims, Empty>::decode_with_jwks(
            &token,
            &jwks,
            Some(SignatureAlgorithm::HS256),
        )
        .expect("to succeed");
    }

    /// JWK has algorithm and user provided a non-matching expected algorithm
    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_with_jwks_shared_secret_mismatched_alg() {
        let token = Compact::decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
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

        let _ = Decoded::<PrivateClaims, Empty>::decode_with_jwks(
            &token,
            &jwks,
            Some(SignatureAlgorithm::RS256),
        )
        .unwrap();
    }

    /// JWK has no algorithm and user provided a header matching expected algorithm
    #[test]
    fn compact_jws_decode_with_jwks_without_alg() {
        let token = Compact::decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
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

        let _ = Decoded::<PrivateClaims, Empty>::decode_with_jwks(
            &token,
            &jwks,
            Some(SignatureAlgorithm::HS256),
        )
        .unwrap();
    }

    /// JWK has no algorithm and user provided a header not-matching expected algorithm
    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_with_jwks_without_alg_non_matching() {
        let token = Compact::decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
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

        let _ = Decoded::<PrivateClaims, Empty>::decode_with_jwks(
            &token,
            &jwks,
            Some(SignatureAlgorithm::RS256),
        )
        .unwrap();
    }

    /// JWK has no algorithm and user did not provide any expected algorithm
    #[test]
    #[should_panic(expected = "MissingAlgorithm")]
    fn compact_jws_decode_with_jwks_missing_alg() {
        let token = Compact::decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
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

        let _ = Decoded::<PrivateClaims, Empty>::decode_with_jwks(&token, &jwks, None).unwrap();
    }

    #[test]
    fn compact_jws_decode_with_jwks_rsa() {
        let token = Compact::decode(
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             MImpi6zezEy0PE5uHU7hM1I0VaNPQx4EAYjEnq2v4gyypmfgKqzrSntSACHZvPsLHDN\
             Ui8PGBM13NcF5IxhybHRM_LVMlMK2rlmQQR7NYueV1psfdSh6fGcYoDxuiZnzybpSxP\
             5Fy8wGe-BgoL5EIPzzhfQBZagzliztLt8RarXHbXnK_KxN1GE5_q5V_ZvjpNr3FExuC\
             cKSvjhlkWR__CmTpv4FWZDkWXJgABLSd0Fe1soUNXMNaqzeTH-xSIYMv06Jckfky6Ds\
             OKcqWyA5QGNScRkSh4fu4jkIiPlituJhFi3hYgIfGTGQMDt2TsiaUCZdfyLhipGwHzmMijeHiQ",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
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

        let _ = Decoded::<PrivateClaims, Empty>::decode_with_jwks(&token, &jwks, None)
            .expect("to succeed");
    }

    #[test]
    #[should_panic(expected = "PartsLengthError { expected: 3, actual: 2 }")]
    fn compact_jws_decode_with_jwks_missing_parts() {
        let token = Compact::decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
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

        let _ = Decoded::<PrivateClaims, Empty>::decode_with_jwks(&token, &jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_with_jwks_wrong_algorithm() {
        let token = Compact::decode(
            "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
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

        let _ = Decoded::<PrivateClaims, Empty>::decode_with_jwks(&token, &jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "KeyNotFound")]
    fn compact_jws_decode_with_jwks_key_not_found() {
        let token = Compact::decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
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

        let _ = Decoded::<PrivateClaims, Empty>::decode_with_jwks(&token, &jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "KidMissing")]
    fn compact_jws_decode_with_jwks_kid_missing() {
        let token = Compact::decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             QhdrScTpNXF2d0RbG_UTWu2gPKZfzANj6XC4uh-wOoU",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
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

        let _ = Decoded::<PrivateClaims, Empty>::decode_with_jwks(&token, &jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnsupportedKeyAlgorithm")]
    fn compact_jws_decode_with_jwks_algorithm_not_supported() {
        let token = Compact::decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
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

        let _ = Decoded::<PrivateClaims, Empty>::decode_with_jwks(&token, &jwks, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnsupportedKeyAlgorithm")]
    fn compact_jws_decode_with_jwks_key_type_not_supported() {
        let token = Compact::decode(
            "eyJhbGciOiAiRVMyNTYiLCJ0eXAiOiAiSldUIiwia2lkIjogImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw",
        );

        let jwks: JWKSet<Empty> = serde_json::from_str(
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

        let _ = Decoded::<PrivateClaims, Empty>::decode_with_jwks(&token, &jwks, None).unwrap();
    }
}
