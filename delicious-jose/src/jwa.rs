//! [JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518)
//!
//! Typically, you will not use these directly, but as part of a JWS or JWE.

use serde::{Deserialize, Serialize};

pub mod cea;
pub mod kma;
pub mod sign;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
/// Algorithms described by [RFC 7518](https://tools.ietf.org/html/rfc7518).
/// This enum is serialized `untagged`.
#[serde(untagged)]
pub enum Algorithm {
    /// Algorithms meant for Digital signature or MACs
    /// See [RFC7518#3](https://tools.ietf.org/html/rfc7518#section-3)
    Signature(sign::Algorithm),
    /// Algorithms meant for key management. The algorithms are either meant to
    /// encrypt a content encryption key or determine the content encryption key.
    /// See [RFC7518#4](https://tools.ietf.org/html/rfc7518#section-4)
    KeyManagement(kma::Algorithm),
    /// Algorithms meant for content encryption.
    /// See [RFC7518#5](https://tools.ietf.org/html/rfc7518#section-5)
    ContentEncryption(cea::Algorithm),
}
