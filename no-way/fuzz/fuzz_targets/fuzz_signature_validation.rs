#![no_main]
#[macro_use]
extern crate libfuzzer_sys;

use no_way::jwa::sign;
use no_way::jwk;
use no_way::jws::{Decoded, Encoded};

fuzz_target!(|data: &[u8]| {
    let key = jwk::OctetKey::new(vec![0; 256 / 8]);

    let token = match std::str::from_utf8(data) {
        Ok(token) => token,
        Err(_) => return,
    };
    let token: Encoded<()> = match token.parse() {
        Ok(token) => token,
        Err(_) => return,
    };
    let _ = Decoded::<()>::decode::<sign::HS256>(token, &key);
});
