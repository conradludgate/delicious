use super::Sign;
use crate::{
    errors::{Error, ValidationError},
    jwk::{EllipticCurve, EllipticCurveKeyParameters},
};
use ecdsa::{SigningKey, VerifyingKey};
use elliptic_curve::{
    sec1::{EncodedPoint, ValidatePublicKey},
    SecretKey,
};
use signature::{Signer, Verifier};
use std::marker::PhantomData;

/// [HMAC with SHA-2 functions](https://datatracker.ietf.org/doc/html/rfc7518#section-3.2)
///
/// See
/// * [`ES256`] - ECDSA using P-256 and SHA-256
/// * [`ES384`] - ECDSA using P-384 and SHA-384
pub struct Ecdsa<P>(PhantomData<P>);

impl<P> PartialEq for Ecdsa<P> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}
impl<P> Eq for Ecdsa<P> {}

impl<P> std::fmt::Debug for Ecdsa<P>
where
    Self: Sign,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(Self::ALG.as_str())
    }
}

/// ECDSA using P-256 and SHA-256
pub type ES256 = Ecdsa<p256::NistP256>;
/// ECDSA using P-384 and SHA-384
pub type ES384 = Ecdsa<p384::NistP384>;

macro_rules! ecdsa {
    ($id:ident, $p:ty, $curve:expr, $n:expr) => {
        impl Sign for $id {
            const ALG: super::Algorithm = super::Algorithm::$id;
            type Key = EllipticCurveKeyParameters;

            fn sign(key: &Self::Key, data: &[u8]) -> Result<Vec<u8>, Error> {
                if key.curve != $curve {
                    return Err(Error::UnspecifiedCryptographicError);
                }
                let mut key_bytes = [0; $n * 2 + 1];
                key.read_pub_sec1_bytes(&mut key_bytes)?;
                let pub_key = EncodedPoint::<$p>::from_bytes(&key_bytes)?;
                key.read_priv_bytes(&mut key_bytes[..$n])?;
                let priv_key = SecretKey::<$p>::from_be_bytes(&key_bytes[..$n])?;
                <$p>::validate_public_key(&priv_key, &pub_key)?;

                Ok(SigningKey::<$p>::from(priv_key).sign(data).to_vec())
            }

            fn verify(key: &Self::Key, data: &[u8], signature: &[u8]) -> Result<(), Error> {
                if key.curve != $curve {
                    return Err(Error::UnspecifiedCryptographicError);
                }
                let mut key_bytes = [0; $n * 2 + 1];
                key.read_pub_sec1_bytes(&mut key_bytes)?;
                let pub_key = VerifyingKey::<$p>::from_sec1_bytes(&key_bytes)?;

                pub_key
                    .verify(data, &signature.try_into()?)
                    .map_err(|_| Error::ValidationError(ValidationError::InvalidSignature))
            }
        }
    };
}

ecdsa!(ES256, p256::NistP256, EllipticCurve::P256, 256 / 8);
ecdsa!(ES384, p384::NistP384, EllipticCurve::P384, 384 / 8);

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::{jwk::EllipticCurveKeyType, test::fromb64};

    use super::*;

    /// Test from https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3
    #[test]
    fn es256() {
        let key = EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve: EllipticCurve::P256,
            x: fromb64("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"),
            y: fromb64("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"),
            d: Some(fromb64("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI")),
        };

        let input = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

        let signature = ES256::sign(&key, input.as_bytes()).unwrap();
        ES256::verify(&key, input.as_bytes(), &signature).unwrap();

        // TODO: this verifies, but why isn't it equal to signature? hmm
        let output = [
            14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3, 58,
            249, 124, 126, 23, 129, 154, 195, 22, 158, 166, 101, 197, 10, 7, 211, 140, 60, 112,
            229, 216, 241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63,
            127, 138, 131, 163, 84, 213,
        ];
        ES256::verify(&key, input.as_bytes(), &output).unwrap();
    }

    /// Test case from https://github.com/briansmith/ring/blob/a13b8e2/src/ec/suite_b/ecdsa_verify_fixed_tests.txt
    #[test]
    fn verify_es256() {
        let payload_bytes = Vec::<u8>::new();
        let pub_key = EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve: EllipticCurve::P256,
            x: hex!("30345FD47EA21A11129BE651B0884BFAC698377611ACC9F689458E13B9ED7D4B").to_vec(),
            y: hex!("9D7599A68DCF125E7F31055CCB374CD04F6D6FD2B217438A63F6F667D50EF2F0").to_vec(),
            d: None,
        };
        let signature = hex!(
            "341F6779B75E98BB42E01095DD48356CBF9002DC704AC8BD2A8240B88D3796C6"
            "555843B1B4E264FE6FFE6E2B705A376C05C09404303FFE5D2711F3E3B3A010A1"
        );
        ES256::verify(&pub_key, &payload_bytes, signature.as_slice()).unwrap();
    }

    /// Test case from https://github.com/briansmith/ring/blob/a13b8e2/src/ec/suite_b/ecdsa_verify_fixed_tests.txt
    #[test]
    fn verify_es384() {
        let payload_bytes = Vec::<u8>::new();
        let pub_key = EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve: EllipticCurve::P384,
            x: hex!("5C5E788A805C77D34128B8401CB59B2373B8B468336C9318252BF39FD31D2507557987A5180A9435F9FB8EB971C426F1").to_vec(),
            y: hex!("C485170DCB18FB688A257F89387A09FC4C5B8BD4B320616B54A0A7B1D1D7C6A0C59F6DFF78C78AD4E3D6FCA9C9A17B96").to_vec(),
            d: None,
        };

        let signature = hex!(
            "85AC708D4B0126BAC1F5EEEBDF911409070A286FDDE5649582611B60046DE353761660DD03903F58B44148F25142EEF8"
            "183475EC1F1392F3D6838ABC0C01724709C446888BED7F2CE4642C6839DC18044A2A6AB9DDC960BFAC79F6988E62D452"
        );
        ES384::verify(&pub_key, &payload_bytes, signature.as_slice()).unwrap();
    }
}
