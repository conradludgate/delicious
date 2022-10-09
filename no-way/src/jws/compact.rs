use std::borrow::Cow;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use base64ct::Encoding;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::errors::{Error, ValidationError};
use crate::jwa::{self, sign};
use crate::jwk;
use crate::{FromCompactPart, Json, ToCompactPart};

use super::Header;

/// Rust representation of a JWS
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unverified<T, H = ()> {
    header: Header<H>,
    payload: T,
    payload_base64: String,
    signature: Vec<u8>,
}

impl<T, H> FromCompactPart for Unverified<T, H>
where
    T: FromCompactPart,
    H: DeserializeOwned,
{
    fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        std::str::from_utf8(b)?.parse()
    }
}
impl<T, H> ToCompactPart for Unverified<T, H>
where
    T: ToCompactPart,
    H: Serialize,
{
    fn to_bytes(&self) -> Result<Cow<'_, [u8]>, Error> {
        Ok(self.to_string().into_bytes().into())
    }
}

impl<T, H> Serialize for Unverified<T, H> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de, T: FromCompactPart, H: DeserializeOwned> serde::Deserialize<'de> for Unverified<T, H> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EncodedVisitor<T, H>(PhantomData<(T, H)>);

        impl<'de, T: FromCompactPart, H: DeserializeOwned> serde::de::Visitor<'de>
            for EncodedVisitor<T, H>
        {
            type Value = Unverified<T, H>;

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

impl<T, H> fmt::Display for Unverified<T, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.payload_base64)?;
        f.write_str(".")?;
        let mut buf = [0; 1024];
        for chunk in self.signature.chunks(1024 / 4 * 3) {
            f.write_str(crate::B64::encode(chunk, &mut buf).unwrap())?;
        }
        Ok(())
    }
}

impl<T, H> FromStr for Unverified<T, H>
where
    T: FromCompactPart,
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

        let (header, payload) = payload_base64.split_once('.').ok_or(Error::DecodeError(
            crate::errors::DecodeError::PartsLengthError {
                expected: 3,
                actual: 2,
            },
        ))?;

        let sig_max_len = (sig.len() + 3) * 3 / 4;
        let head_max_len = (header.len() + 3) * 3 / 4;
        let payload_max_len = (payload.len() + 3) * 3 / 4;
        let max_len = sig_max_len.max(head_max_len).max(payload_max_len);
        let mut alloc = vec![0; max_len];

        let header = Header::from_bytes(crate::B64::decode(header, &mut alloc)?)?;
        let payload = T::from_bytes(crate::B64::decode(payload, &mut alloc)?)?;
        let sig_len = crate::B64::decode(sig, &mut alloc)?.len();
        alloc.truncate(sig_len);

        Ok(Self {
            header,
            payload,
            payload_base64: payload_base64.to_owned(),
            signature: alloc,
        })
    }
}

impl<T, H> Unverified<Json<T>, H> {
    pub fn header(&self) -> &Header<H> {
        &self.header
    }
}
impl<T, H> Unverified<Json<T>, H>
where
    T: Serialize + DeserializeOwned,
    H: Serialize + DeserializeOwned,
{
    /// Verify that the token has a valid signature
    pub fn verify_json<Sign: sign::Sign>(self, key: &Sign::Key) -> Result<Verified<T, H>, Error> {
        let Verified { header, payload } = self.verify::<Sign>(key)?;
        Ok(Verified::new_with_header(payload.0, header))
    }
}
impl<T, H> Unverified<T, H> {
    /// Verify that the token has a valid signature
    pub fn verify<Sign: sign::Sign>(self, key: &Sign::Key) -> Result<Verified<T, H>, Error> {
        let Self {
            header,
            payload,
            payload_base64,
            signature,
        } = self;

        if header.registered.algorithm != Sign::ALG {
            Err(ValidationError::WrongAlgorithmHeader)?;
        }

        Sign::verify(key, payload_base64.as_bytes(), &signature)?;

        Ok(Verified::new_with_header(payload, header.private))
    }

    /// Verify that the token has a valid signature. It determines the key to use from the `JWKSet` by
    /// checking the `kid` and validating that all the `alg` headers match.
    pub fn verify_with_jwks<J, Sign>(self, jwks: &jwk::JWKSet<J>) -> Result<Verified<T, H>, Error>
    where
        Sign: sign::Sign,
        Sign::Key: jwk::Key,
    {
        let Header {
            registered,
            private,
        } = self.header;

        let key_id = registered.key_id;
        let key_id = key_id.as_deref().ok_or(ValidationError::KidMissing)?;
        let jwk = jwks.find(key_id).ok_or(ValidationError::KeyNotFound)?;

        match jwk.specified.common.algorithm {
            None => {}
            Some(jwa::Algorithm::Signature(s)) if s == Sign::ALG => {}
            Some(_) => return Err(ValidationError::UnsupportedKeyAlgorithm.into()),
        }

        if registered.algorithm != Sign::ALG {
            return Err(ValidationError::WrongAlgorithmHeader.into());
        }

        let key = <Sign::Key as jwk::Key>::from(&jwk.specified)?;
        Sign::verify(key, self.payload_base64.as_bytes(), &self.signature)?;

        Ok(Verified::new_with_header(self.payload, private))
    }
}

/// Rust representation of a JWS
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verified<T, H = ()> {
    /// Embedded header
    pub header: H,
    /// Payload, usually a claims set
    pub payload: T,
}

impl<T, H> Verified<T, H>
where
    T: Serialize + DeserializeOwned,
    H: Serialize + DeserializeOwned,
{
    /// Encode the JWT passed and sign the payload using the algorithm from the header and the secret
    /// The secret is dependent on the signing algorithm
    pub fn encode_json<Sign: sign::Sign>(
        self,
        key: &Sign::Key,
    ) -> Result<Unverified<Json<T>, H>, Error> {
        let Self { header, payload } = self;
        Verified {
            header,
            payload: Json(payload),
        }
        .encode::<Sign>(key)
    }
}

impl<T> Verified<T> {
    /// New decoded JWT
    pub fn new(payload: T) -> Self {
        Self::new_with_header(payload, ())
    }
}
impl<T, H> Verified<T, H> {
    /// New decoded JWT
    pub fn new_with_header(payload: T, header: H) -> Self {
        Self { header, payload }
    }
}
impl<T, H> Verified<T, H>
where
    T: ToCompactPart,
    H: Serialize,
{
    /// Encode the JWT passed and sign the payload using the algorithm from the header and the secret
    /// The secret is dependent on the signing algorithm
    pub fn encode<Sign: sign::Sign>(self, key: &Sign::Key) -> Result<Unverified<T, H>, Error> {
        let Self { header, payload } = self;
        let header = Header {
            private: header,
            registered: super::RegisteredHeader {
                algorithm: Sign::ALG,
                ..Default::default()
            },
        };

        let h = header.to_bytes()?;
        let p = payload.to_bytes()?;

        let mut p64 = vec![0; (h.len() * 4 / 3) + (p.len() * 4 / 3) + 9];
        let n = crate::B64::encode(&h, &mut p64).unwrap().len();
        let m = crate::B64::encode(&p, &mut p64[n + 1..]).unwrap().len();
        p64[n] = b'.';
        p64.truncate(n + m + 1);

        let signature = Sign::sign(key, &p64)?;

        // safety: payload_base64 is a valid utf8 string
        let payload_base64 = unsafe { String::from_utf8_unchecked(p64) };

        Ok(Unverified {
            header,
            payload,
            payload_base64,
            signature,
        })
    }
}

/// Convenience implementation for a Compact that contains a `ClaimsSet`
impl<P, H> Verified<crate::ClaimsSet<P>, H>
where
    crate::ClaimsSet<P>: Serialize + DeserializeOwned,
    H: Serialize + DeserializeOwned,
{
    /// Validate the temporal claims in the decoded token
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

    use hex_literal::hex;
    use serde::{Deserialize, Serialize};

    use super::{sign, Unverified, Verified};
    use crate::errors::Error;
    use crate::jwk::{
        EllipticCurve, EllipticCurveKeyParameters, EllipticCurveKeyType, JWKSet, OctetKey,
    };
    use crate::{ClaimsSet, FromCompactPart, RegisteredClaims, ToCompactPart};

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct PrivateClaims {
        company: String,
        department: String,
    }

    impl FromCompactPart for PrivateClaims {
        fn from_bytes(b: &[u8]) -> Result<Self, Error> {
            Ok(serde_json::from_slice(b)?)
        }
    }
    impl ToCompactPart for PrivateClaims {
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
                issuer: Some("https://www.acme.com/".into()),
                subject: Some("John Doe".into()),
                audience: Some("https://acme-customer.com/".into()),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let expected_jwt = Verified::new(expected_claims.clone());
        let token = expected_jwt.encode::<sign::None>(&()).unwrap();
        assert_eq!(expected_token, token.to_string());

        let biscuit = token.verify::<sign::None>(&()).unwrap();
        assert_eq!(expected_claims, biscuit.payload);
    }

    #[test]
    fn compact_jws_round_trip_hs256() {
        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some("https://www.acme.com/".into()),
                subject: Some("John Doe".into()),
                audience: Some("https://acme-customer.com/".into()),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let key = OctetKey::new("secret".to_string().into_bytes());
        let expected_jwt = Verified::new(expected_claims.clone());
        let token = expected_jwt.encode::<sign::HS256>(&key).unwrap();
        assert_eq!(HS256_PAYLOAD, token.to_string());

        let biscuit = token.verify::<sign::HS256>(&key).unwrap();
        assert_eq!(expected_claims, biscuit.payload);
    }

    // #[test]
    // fn compact_jws_round_trip_rs256() {
    //     let expected_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
    //                           eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1Z\
    //                           CI6Imh0dHBzOi8vYWNtZS1jdXN0b21lci5jb20vIiwibmJmIjoxMjM0LCJjb21wYW55Ij\
    //                           oiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
    //                           Gat3NBUTaCyvroil66U0nId4-l6VqbtJYIsM9wRbWo45oYoN-NxYIyl8M-9AlEPseg-4SIuo-A-jccJOWGeWWwy-E\
    //                           en_92wg18II58luHz7vAyclw1maJBKHmuj8f2wE_Ky8ir3iTpTGkJQ3IUU9SuU9Fkvajm4jgWUtRPpjHm_IqyxV8N\
    //                           kHNyN0p5CqeuRC8sZkOSFkm9b0WnWYRVls1QOjBnN9w9zW9wg9DGwj10pqg8hQ5sy-C3J-9q1zJgGDXInkhPLjitO\
    //                           9wzWg4yfVt-CJNiHsJT7RY_EN2VmbG8UOjHp8xUPpfqUKyoQttKaQkJHdjP_b47LO4ZKI4UivlA";

    //     let expected_claims = ClaimsSet::<PrivateClaims> {
    //         registered: RegisteredClaims {
    //             issuer: Some("https://www.acme.com/".into()),
    //             subject: Some("John Doe".into()),
    //             audience: Some(SingleOrMultiple::Single(
    //                 FromStr::from_str("https://acme-customer.com/").unwrap(),
    //             )),
    //             not_before: Some(1234.try_into().unwrap()),
    //             ..Default::default()
    //         },
    //         private: PrivateClaims {
    //             department: "Toilet Cleaning".to_string(),
    //             company: "ACME".to_string(),
    //         },
    //     };
    //     let private_key =
    //         Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();

    //     let expected_jwt = Decoded::new(
    //         From::from(RegisteredHeader {
    //             algorithm: sign::Algorithm::RS256,
    //             ..Default::default()
    //         }),
    //         expected_claims.clone(),
    //     );
    //     let token = expected_jwt.encode(&private_key).unwrap();
    //     assert_eq!(expected_token, token.to_string());

    //     let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
    //     let biscuit: Decoded<_, ()> =
    //         Decoded::decode(token, &public_key, sign::Algorithm::RS256).unwrap();
    //     assert_eq!(expected_claims, biscuit.payload);
    // }

    #[test]
    fn compact_jws_verify_es256() {
        let public_key = EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve: EllipticCurve::P256,
            x: hex!("3727F96AAD416887DD75CC2E333C3D8E06DCDF968B6024579449A2B802EFC891").to_vec(),
            y: hex!("F638C751CF687E6FF9A280E11B7036585E60CA32BB469C3E57998A289E0860A6").to_vec(),
            d: None,
        };

        let jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.\
                   eyJ0b2tlbl90eXBlIjoic2VydmljZSIsImlhdCI6MTQ5MjkzODU4OH0.\
                   do_XppIOFthPWlTXL95CIBfgRdyAxbcIsUfM0YxMjCjqvp4ehHFA3I-JasABKzC8CAy4ndhCHsZdpAtK\
                   kqZMEA";

        let token: Unverified<ClaimsSet<serde_json::Value>> = jwt.parse().unwrap();
        token.verify::<sign::ES256>(&public_key).unwrap();
    }

    #[test]
    fn compact_jws_encode_with_additional_header_fields() {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct CustomHeader {
            something: String,
        }

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some("https://www.acme.com/".into()),
                subject: Some("John Doe".into()),
                audience: Some("https://acme-customer.com/".into()),
                not_before: Some(1234.try_into().unwrap()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let key = OctetKey::new("secret".to_string().into_bytes());
        let header = CustomHeader {
            something: "foobar".to_string(),
        };

        let expected_jwt = Verified::new_with_header(expected_claims, header.clone());

        let token = expected_jwt.encode::<sign::HS256>(&key).unwrap();
        let biscuit = token.verify::<sign::HS256>(&key).unwrap();
        assert_eq!(header, biscuit.header);
    }

    #[test]
    #[should_panic(expected = "PartsLengthError { expected: 3, actual: 1 }")]
    fn compact_jws_decode_token_missing_parts() {
        Unverified::<()>::from_str("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9").unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn compact_jws_decode_token_invalid_signature_hs256() {
        let token: Unverified<PrivateClaims> = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJkZXBhcnRtZW50IjoiQ3J5cHRvIn0.\
             pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI"
            .parse()
            .unwrap();
        let key = OctetKey::new("secret".to_string().into_bytes());
        token.verify::<sign::HS256>(&key).unwrap();
    }

    // #[test]
    // #[should_panic(expected = "InvalidSignature")]
    // fn compact_jws_decode_token_invalid_signature_rs256() {
    //     let token = Encoded::from_str(
    //         "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
    //          eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJkZXBhcnRtZW50IjoiQ3J5cHRvIn0.\
    //          pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI",
    //     )
    //     .unwrap();
    //     let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
    //     let claims =
    //         Decoded::<PrivateClaims>::decode(token, &public_key, sign::Algorithm::RS256);
    //     let _ = claims.unwrap();
    // }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_token_wrong_algorithm() {
        let token: Unverified<PrivateClaims> = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.\
             eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJkZXBhcnRtZW50IjoiQ3J5cHRvIn0.\
             pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI"
            .parse()
            .unwrap();

        let key = OctetKey::new("secret".to_string().into_bytes());
        token.verify::<sign::HS256>(&key).unwrap();
    }

    #[test]
    fn compact_jws_round_trip_hs256_for_bytes_payload() {
        let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
            eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
            xr9g55zVt0hfdTgkbONHNH6mT1J8Dhs7APzo3BuVb24";
        let payload: Vec<u8> = vec![
            123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120,
            112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116,
            112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95,
            114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
        ];

        let key = OctetKey::new("secret".to_string().into_bytes());
        let expected_jwt = Verified::new(payload.clone());
        let token = expected_jwt.encode::<sign::HS256>(&key).unwrap();
        assert_eq!(expected_token, token.to_string());

        let biscuit = token.verify::<sign::HS256>(&key).unwrap();
        assert_eq!(payload, biscuit.payload);
    }

    #[test]
    fn compact_jws_decode_with_jwks_shared_secret() {
        let token: Unverified<PrivateClaims> =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw"
                .parse()
                .unwrap();

        let jwks: JWKSet = serde_json::from_str(
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

        token.verify_with_jwks::<_, sign::HS256>(&jwks).unwrap();
    }

    /// JWK has algorithm and user provided a non-matching expected algorithm
    #[test]
    #[should_panic(expected = "UnsupportedKeyAlgorithm")]
    fn compact_jws_decode_with_jwks_shared_secret_mismatched_alg() {
        let token: Unverified<PrivateClaims> =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw"
                .parse()
                .unwrap();

        let jwks: JWKSet = serde_json::from_str(
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

        token.verify_with_jwks::<_, sign::ES256>(&jwks).unwrap();
    }

    /// JWK has no algorithm and user provided a header matching expected algorithm
    #[test]
    fn compact_jws_decode_with_jwks_without_alg() {
        let token: Unverified<PrivateClaims> =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw"
                .parse()
                .unwrap();

        let jwks: JWKSet = serde_json::from_str(
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

        token.verify_with_jwks::<_, sign::HS256>(&jwks).unwrap();
    }

    /// JWK has no algorithm and user provided a header not-matching expected algorithm
    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn compact_jws_decode_with_jwks_without_alg_non_matching() {
        let token: Unverified<PrivateClaims> =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw"
                .parse()
                .unwrap();

        let jwks: JWKSet = serde_json::from_str(
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

        token.verify_with_jwks::<_, sign::ES256>(&jwks).unwrap();
    }

    // #[test]
    // fn compact_jws_decode_with_jwks_rsa() {
    //     let token = Encoded::from_str(
    //         "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
    //          eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
    //          MImpi6zezEy0PE5uHU7hM1I0VaNPQx4EAYjEnq2v4gyypmfgKqzrSntSACHZvPsLHDN\
    //          Ui8PGBM13NcF5IxhybHRM_LVMlMK2rlmQQR7NYueV1psfdSh6fGcYoDxuiZnzybpSxP\
    //          5Fy8wGe-BgoL5EIPzzhfQBZagzliztLt8RarXHbXnK_KxN1GE5_q5V_ZvjpNr3FExuC\
    //          cKSvjhlkWR__CmTpv4FWZDkWXJgABLSd0Fe1soUNXMNaqzeTH-xSIYMv06Jckfky6Ds\
    //          OKcqWyA5QGNScRkSh4fu4jkIiPlituJhFi3hYgIfGTGQMDt2TsiaUCZdfyLhipGwHzmMijeHiQ",
    //     )
    //     .unwrap();

    //     let jwks: JWKSet = serde_json::from_str(
    //         r#"{
    //         "keys": [
    //                     {
    //                         "kty": "RSA",
    //                         "e": "AQAB",
    //                         "use": "sig",
    //                         "kid": "key0",
    //                         "alg": "RS256",
    //                         "n": "rx7xQsC4XuzCW1YZwm3JUftsScV3v82VmuuIcmUOBGyLpeChfHwwr61UZOVL6yiFSIoGlS1KbVkyZ5xf8FCQGdRuAYvx2sH4E0D9gOdjAauXIx7ADbG5wfTHqiyYcWezovzdXZb4F7HCaBkaKhtg8FTkTozQz5m6stzcFatcSUZpNM6lCSGoi0kFfucEAV2cNoWUaW1WnYyGB2sxupSIako9updQIHfAqiDSbawO8uBymNjiQJS3evImjLcJajAYzrmK1biSu5uJuw3RReYef3QUvLY9o2T6LV3QiIWi3MeBktjhwAvCKzcOeU34py946AJm6USXkwit_hlFx5DzgQ"
    //                     }
    //         ]
    //     }"#,
    //     )
    //     .unwrap();

    //     Decoded::<PrivateClaims>::decode_with_jwks(token, &jwks, None).unwrap();
    // }

    #[test]
    #[should_panic(expected = "PartsLengthError { expected: 3, actual: 2 }")]
    fn compact_jws_decode_with_jwks_missing_parts() {
        Unverified::<PrivateClaims>::from_str(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ",
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "KeyNotFound")]
    fn compact_jws_decode_with_jwks_key_not_found() {
        let token: Unverified<PrivateClaims> =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw"
                .parse()
                .unwrap();

        let jwks: JWKSet = serde_json::from_str(
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

        token.verify_with_jwks::<_, sign::HS256>(&jwks).unwrap();
    }

    #[test]
    #[should_panic(expected = "KidMissing")]
    fn compact_jws_decode_with_jwks_kid_missing() {
        let token: Unverified<PrivateClaims> = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             QhdrScTpNXF2d0RbG_UTWu2gPKZfzANj6XC4uh-wOoU"
            .parse()
            .unwrap();

        let jwks: JWKSet = serde_json::from_str(
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

        token.verify_with_jwks::<_, sign::HS256>(&jwks).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnsupportedKeyAlgorithm")]
    fn compact_jws_decode_with_jwks_algorithm_not_supported() {
        let token: Unverified<PrivateClaims> =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw"
                .parse()
                .unwrap();

        let jwks: JWKSet = serde_json::from_str(
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

        token.verify_with_jwks::<_, sign::HS256>(&jwks).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnsupportedKeyAlgorithm")]
    fn compact_jws_decode_with_jwks_key_type_not_supported() {
        let token: Unverified<PrivateClaims> =
            "eyJhbGciOiAiRVMyNTYiLCJ0eXAiOiAiSldUIiwia2lkIjogImtleTAifQ.\
             eyJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ.\
             nz0a8aSweo6W0K2P7keByUPWl0HLVG45pTDznij5uKw"
                .parse()
                .unwrap();

        let jwks: JWKSet = serde_json::from_str(
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

        token.verify_with_jwks::<_, sign::HS256>(&jwks).unwrap();
    }
}
