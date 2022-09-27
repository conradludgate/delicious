#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate delicious_jose;
extern crate serde_json;

use delicious_jose::*;
use delicious_jose::jws::*;
use delicious_jose::jwa::*;

fuzz_target!(|data: &[u8]| {
    let signing_secret = Secret::Bytes("secret".to_string().into_bytes());
    
    let token = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return,
    };

    let token = Compact::decode(token);
    let _ = JWT::<serde_json::Value, delicious_jose::()>::decode(&token, &signing_secret, SignatureAlgorithm::HS256);
});
