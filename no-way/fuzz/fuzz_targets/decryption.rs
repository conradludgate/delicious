#![no_main]
#[macro_use]
extern crate libfuzzer_sys;

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
                nonce: vec![0,1,2,3,4,5,6,7,8,9,10,11],
                tag: vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
            },
            private: (),
        };
        let header = serde_json::to_string(&header).unwrap();

        let mut token = String::new();
        base64::encode_config_buf(header, base64::URL_SAFE_NO_PAD, &mut token);
        token.push('.');
        base64::encode_config_buf(encrypted_cek, base64::URL_SAFE_NO_PAD, &mut token);
        token.push('.');
        base64::encode_config_buf(iv, base64::URL_SAFE_NO_PAD, &mut token);
        token.push('.');
        // no payload
        token.push('.');
        base64::encode_config_buf(tag, base64::URL_SAFE_NO_PAD, &mut token);

        // token should be valid
        let token: Encrypted<kma::A256GCMKW> = token.parse().unwrap();

        // random key and payload should never validate
        let key = jwk::OctetKey::new(key.to_vec());
        let err = token.decrypt::<(), cea::A256GCM>(&key).unwrap_err();
        assert!(matches!(err, errors::Error::UnspecifiedCryptographicError));
    }
);
