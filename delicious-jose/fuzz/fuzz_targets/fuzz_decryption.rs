#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate delicious_jose;
extern crate serde_json;

use delicious_jose::jwa::{ContentEncryptionAlgorithm, KeyManagementAlgorithm};
use delicious_jose::jwk::JWK;
use delicious_jose::{Compact, Empty, JWE};

fuzz_target!(|data: &[u8]| {
    let key: JWK<Empty> = JWK::new_octet_key(&vec![0; 256 / 8], Default::default());

    let token = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return,
    };

    let token = Compact::decode(token);

    let _ = JWE::<delicious_jose::Empty>::decrypt(
        &token,
        &key,
        KeyManagementAlgorithm::A256GCMKW,
        ContentEncryptionAlgorithm::A256GCM,
    );
});
