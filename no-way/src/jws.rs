//! [JSON Web Signatures](https://tools.ietf.org/html/rfc7515), including JWT signing and headers
mod compact;
// mod flattened;

pub use compact::{Unverified, Verified};
// pub use flattened::{Signable, SignedData};
use serde::de::DeserializeOwned;

use crate::errors::Error;
use crate::jwa::sign;
use crate::jwk;
use crate::{FromCompactPart, ToCompactPart};

use serde::{self, Deserialize, Serialize};
use std::borrow::Cow;

/// JWS Header, consisting of the registered fields and other custom fields
#[derive(Debug, Eq, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct Header<T = ()> {
    /// Registered header fields
    #[serde(flatten)]
    pub registered: RegisteredHeader,
    /// Private header fields
    #[serde(flatten)]
    pub private: T,
}

impl<T: DeserializeOwned> FromCompactPart for Header<T> {
    fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(serde_json::from_slice(b)?)
    }
}
impl<T: Serialize> ToCompactPart for Header<T> {
    fn to_bytes(&self) -> Result<Cow<'_, [u8]>, Error> {
        Ok(serde_json::to_vec(&self)?.into())
    }
}

// impl<T: Serialize + DeserializeOwned> CompactJson for Header<T> {}

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Registered JWS header fields.
/// The alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional.
/// The fields are defined by [RFC7519#5](https://tools.ietf.org/html/rfc7519#section-5) and additionally in
/// [RFC7515#4.1](https://tools.ietf.org/html/rfc7515#section-4.1).
// TODO: Implement verification for registered headers and support custom headers
pub struct RegisteredHeader {
    /// Algorithms, as defined in [RFC 7518](https://tools.ietf.org/html/rfc7518), used to sign or encrypt the JWT
    /// Serialized to `alg`.
    /// Defined in [RFC7515#4.1.1](https://tools.ietf.org/html/rfc7515#section-4.1.1).
    #[serde(rename = "alg")]
    pub algorithm: sign::Algorithm,

    /// Media type of the complete JWS. Serialized to `typ`.
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

    /// The JSON Web Key.
    /// Serialized to `jwk`.
    /// Defined in [RFC7515#4.1.3](https://tools.ietf.org/html/rfc7515#section-4.1.3).
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub web_key: Option<jwk::JWK<()>>,

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

impl Default for RegisteredHeader {
    fn default() -> RegisteredHeader {
        RegisteredHeader {
            algorithm: sign::Algorithm::default(),
            media_type: Some("JWT".to_string()),
            content_type: None,
            web_key_url: None,
            web_key: None,
            key_id: None,
            x509_url: None,
            x509_chain: None,
            x509_fingerprint: None,
            critical: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RegisteredHeader;

    #[test]
    fn header_serialization_round_trip_no_optional() {
        let expected = RegisteredHeader::default();
        let expected_json = r#"{"alg":"HS256","typ":"JWT"}"#;

        let encoded = serde_json::to_string(&expected).unwrap();
        assert_eq!(expected_json, encoded);

        let decoded: RegisteredHeader = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn header_serialization_round_trip_with_optional() {
        let expected = RegisteredHeader {
            key_id: Some("kid".to_string()),
            ..Default::default()
        };

        let expected_json = r#"{"alg":"HS256","typ":"JWT","kid":"kid"}"#;

        let encoded = serde_json::to_string(&expected).unwrap();
        assert_eq!(expected_json, encoded);

        let decoded: RegisteredHeader = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, expected);
    }
}
