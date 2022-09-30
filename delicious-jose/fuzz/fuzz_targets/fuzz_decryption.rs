#![no_main]
#[macro_use]
extern crate libfuzzer_sys;

use delicious_jose::jwa::{cea, kma};
use delicious_jose::jwe::Encrypted;
use delicious_jose::jwk;

fuzz_target!(|data: &[u8]| {
    let key = jwk::OctetKey::new(vec![0; 256 / 8]);

    let token = match std::str::from_utf8(data) {
        Ok(token) => token,
        Err(_) => return,
    };
    let token: Encrypted<kma::A256GCMKW> = match token.parse() {
        Ok(token) => token,
        Err(_) => return,
    };
    let _ = token.decrypt::<(), cea::A256GCM>(&key);
});
