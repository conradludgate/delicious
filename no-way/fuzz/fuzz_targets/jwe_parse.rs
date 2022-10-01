#![no_main]
use libfuzzer_sys::fuzz_target;

use no_way::{
    errors,
    jwa::{cea, kma},
    jwe::Encrypted,
    jwk,
};

fuzz_target!(|data: ([u8; 256 / 8], &str)| {
    let (key, token) = data;

    // parsing a jwe string shouldn't panic
    let token: Encrypted<kma::A256GCMKW> = match token.parse() {
        Ok(token) => token,
        Err(_) => return,
    };

    // random key and payload should never validate
    let key = jwk::OctetKey::new(key.to_vec());
    let err = token.decrypt::<(), cea::A256GCM>(&key).unwrap_err();
    assert!(matches!(err, errors::Error::UnspecifiedCryptographicError));
});
