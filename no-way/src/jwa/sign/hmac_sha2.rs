use super::Sign;
use crate::{
    errors::{Error, ValidationError},
    jwk::OctetKey,
};
use hmac::{Hmac, Mac};
use std::marker::PhantomData;

/// [HMAC with SHA-2 functions](https://datatracker.ietf.org/doc/html/rfc7518#section-3.2)
///
/// See
/// * [`HS256`] - HMAC using SHA-256
/// * [`HS384`] - HMAC using SHA-384
/// * [`HS512`] - HMAC using SHA-512
pub struct HmacSha<Sha>(PhantomData<Sha>);

impl<Sha> Clone for HmacSha<Sha> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<Sha> Copy for HmacSha<Sha> {}

impl<Sha> PartialEq for HmacSha<Sha> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}
impl<Sha> Eq for HmacSha<Sha> {}

impl<Sha> std::fmt::Debug for HmacSha<Sha>
where
    Self: Sign,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(Self::ALG.as_str())
    }
}

/// HMAC using SHA-256
pub type HS256 = HmacSha<sha2::Sha256>;
/// HMAC using SHA-384
pub type HS384 = HmacSha<sha2::Sha384>;
/// HMAC using SHA-512
pub type HS512 = HmacSha<sha2::Sha512>;

macro_rules! hmac_sha {
    ($id:ident, $sha:ty) => {
        impl Sign for $id {
            const ALG: super::Algorithm = super::Algorithm::$id;
            type Key = OctetKey;

            fn sign(key: &Self::Key, data: &[u8]) -> Result<Vec<u8>, Error> {
                Ok(Hmac::<$sha>::new_from_slice(key.as_bytes())?
                    .chain_update(data)
                    .finalize()
                    .into_bytes()
                    .to_vec())
            }

            fn verify(key: &Self::Key, data: &[u8], signature: &[u8]) -> Result<(), Error> {
                Hmac::<$sha>::new_from_slice(key.as_bytes())?
                    .chain_update(data)
                    .verify_slice(signature)
                    .map_err(|_| Error::ValidationError(ValidationError::InvalidSignature))
            }
        }
    };
}

hmac_sha!(HS256, sha2::Sha256);
hmac_sha!(HS384, sha2::Sha384);
hmac_sha!(HS512, sha2::Sha512);

#[cfg(test)]
mod tests {
    use base64ct::Encoding;

    use super::*;

    #[test]
    fn sign_and_verify_hs256() {
        let expected_base64 = "uC_LeRrOxXhZuYm0MKgmSIzi5Hn9-SMmvQoug3WkK6Q";
        let expected_bytes: Vec<u8> = crate::B64::decode_vec(expected_base64).unwrap();

        let key = OctetKey::new(b"secret".to_vec());
        let payload = b"payload";
        let actual_signature = HS256::sign(&key, payload).unwrap();
        HS256::verify(&key, payload, &actual_signature).unwrap();

        assert_eq!(actual_signature, expected_bytes);
    }
}
