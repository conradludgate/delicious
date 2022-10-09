#![no_main]
#[macro_use]
extern crate libfuzzer_sys;

use base64ct::Encoding;
use no_way::{
    errors,
    jwa::{cea, kma},
    jwe::Encrypted,
    jwk,
};

fuzz_target!(
    |data: ([u8; 256 / 8], [u8; 256 / 8], [u8; 96 / 8], &[u8])| {
        let (key, encrypted_cek, iv, tag) = data;

        let header = no_way::jwe::Header::<kma::AesGcmKwHeader> {
            registered: no_way::jwe::RegisteredHeader {
                cek_algorithm: kma::Algorithm::AesGcmKw(kma::AesGcmKwAlgorithm::A256),
                enc_algorithm: cea::Algorithm::A256GCM,
                ..Default::default()
            },
            kma: kma::AesGcmKwHeader {
                iv: [0,1,2,3,4,5,6,7,8,9,10,11],
                tag: [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
            },
            private: (),
        };
        let header = serde_json::to_string(&header).unwrap();

        let mut token = String::new();
        token.push_str(&base64ct::Base64UrlUnpadded::encode_string(header.as_bytes()));
        token.push('.');
        token.push_str(&base64ct::Base64UrlUnpadded::encode_string(&encrypted_cek));
        token.push('.');
        token.push_str(&base64ct::Base64UrlUnpadded::encode_string(&iv));
        token.push('.');
        // no payload
        token.push('.');
        token.push_str(&base64ct::Base64UrlUnpadded::encode_string(&tag));

        // token should be valid
        let token: Encrypted<kma::A256GCMKW> = token.parse().unwrap();

        // random key and payload should never validate
        let key = jwk::OctetKey::new(key.to_vec());
        let err = token.decrypt::<(), cea::A256GCM>(&key).unwrap_err();
        assert!(matches!(err, errors::Error::UnspecifiedCryptographicError));
    }
);
