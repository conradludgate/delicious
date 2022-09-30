#![no_main]
#[macro_use]
extern crate libfuzzer_sys;

use no_way::jwa::{cea, kma};
use no_way::jwe::Encrypted;
use no_way::jwk;

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
