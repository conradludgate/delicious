#![no_main]
#[macro_use]
extern crate libfuzzer_sys;

use base64ct::Encoding;
use no_way::{errors, jwa::sign, jwk, jws::Unverified};

fuzz_target!(|data: ([u8; 256 / 8], &[u8])| {
    let (key, signature) = data;

    let mut token = "eyJhbGciOiJIUzI1NiJ9..".to_owned();
    token.push_str(&base64ct::Base64UrlUnpadded::encode_string(signature));

    // token should be valid
    let token: Unverified<()> = token.parse().unwrap();

    // random key and signature should never validate
    let key = jwk::OctetKey::new(key.to_vec());
    let err = token.verify::<sign::HS256>(&key).unwrap_err();
    assert!(matches!(
        err,
        errors::Error::ValidationError(errors::ValidationError::InvalidSignature)
    ));
});
