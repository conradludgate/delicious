#![no_main]
use libfuzzer_sys::fuzz_target;

use no_way::{errors, jwa::sign, jwk, jws::Unverified};

fuzz_target!(|data: ([u8; 256 / 8], &str)| {
    let (key, token) = data;

    // parsing a jwe string shouldn't panic
    let token: Unverified<()> = match token.parse() {
        Ok(token) => token,
        Err(_) => return,
    };

    // random key and signature should never validate
    let key = jwk::OctetKey::new(key.to_vec());
    let err = token.verify::<sign::HS256>(&key).unwrap_err();
    assert!(matches!(
        err,
        errors::Error::ValidationError(errors::ValidationError::InvalidSignature)
    ));
});
