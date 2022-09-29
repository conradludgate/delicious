use std::marker::PhantomData;

use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use cipher::block_padding::Pkcs7;
use hmac::Hmac;

use crate::{
    errors::Error,
    jwa::{
        ContentEncryptionAlgorithm, EncryptionOptions, EncryptionResult, OctetKey,
        AES_CBC_HMAC_SHA_ZEROED_NONCE,
    },
    jwk,
};

use super::CEA;

/// [Content Encryption with AES_CBC_HMAC_SHA2](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2)
pub struct AesCbcHmacSha2<Aes, Sha> {
    _sha: PhantomData<Sha>,
    _aes: PhantomData<Aes>,
}

#[allow(non_camel_case_types)]
/// [Content Encryption with AES_128_CBC_HMAC_SHA_256](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.3)
pub type A128CBC_HS256 = AesCbcHmacSha2<aes::Aes128, sha2::Sha256>;
#[allow(non_camel_case_types)]
/// [Content Encryption with AES_192_CBC_HMAC_SHA_384](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.4)
pub type A192CBC_HS384 = AesCbcHmacSha2<aes::Aes192, sha2::Sha384>;
#[allow(non_camel_case_types)]
/// [Content Encryption with AES_256_CBC_HMAC_SHA_512](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.5)
pub type A256CBC_HS512 = AesCbcHmacSha2<aes::Aes256, sha2::Sha512>;

macro_rules! aes_cbc {
    ($sha:ty, $aes:ty, $name:literal, $key_len:expr) => {
impl CEA for AesCbcHmacSha2<$aes, $sha> {
    const ENC: &'static str = $name;

    type Cek = OctetKey;

    fn encrypt(
        cek: Self::Cek,
        payload: &[u8],
        iv: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<EncryptionResult, Error> {
        use aes::cipher::KeyIvInit;
        use hmac::Mac;

        if cek.0.len() != $key_len * 2 {
            return Err(Error::UnspecifiedCryptographicError);
        }

        let (mac_key, enc_key) = cek.0.split_at($key_len);

        // encrypt the payload using aes-cbc
        let encrypted = cbc::Encryptor::<$aes>::new_from_slices(enc_key, &iv)?
            .encrypt_padded_vec_mut::<Pkcs7>(payload);

        // compute the hmac
        let tag = Hmac::<$sha>::new_from_slice(mac_key)?
            .chain_update(&aad)
            .chain_update(&iv)
            .chain_update(&encrypted)
            .chain_update(&(aad.len() as u64 * 8).to_be_bytes())
            .finalize()
            .into_bytes()[..$key_len]
            .to_vec();

        Ok(EncryptionResult {
            nonce: iv,
            encrypted,
            tag,
            additional_data: aad,
        })
    }

    fn decrypt(cek: Self::Cek, res: &EncryptionResult) -> Result<Vec<u8>, Error> {
        use aes::cipher::KeyIvInit;
        use hmac::Mac;

        let EncryptionResult {
            nonce,
            encrypted,
            tag,
            additional_data: aad,
        } = res;

        if cek.0.len() != $key_len * 2 || tag.len() != $key_len {
            return Err(Error::UnspecifiedCryptographicError);
        }
        let (mac_key, enc_key) = cek.0.split_at($key_len);

        // validate the hmac
        Hmac::<$sha>::new_from_slice(mac_key)?
            .chain_update(&aad)
            .chain_update(&nonce)
            .chain_update(&encrypted)
            .chain_update(&(aad.len() as u64 * 8).to_be_bytes())
            .verify_truncated_left(&tag)?;

        // decrypt the payload using aes-cbc
        let decrypted = cbc::Decryptor::<$aes>::new_from_slices(enc_key, &nonce)?
            .decrypt_padded_vec_mut::<Pkcs7>(&encrypted)?;
        Ok(decrypted)
    }
} 
    };
}

aes_cbc!(sha2::Sha256, aes::Aes128, "A128CBC-HS256", 128 / 8);
aes_cbc!(sha2::Sha384, aes::Aes192, "A192CBC-HS384", 192 / 8);
aes_cbc!(sha2::Sha512, aes::Aes256, "A256CBC-HS512", 256 / 8);

impl ContentEncryptionAlgorithm {
    pub(crate) fn aes_cbc_encrypt(
        self,
        payload: &[u8],
        aad: &[u8],
        key: &jwk::Specified,
        options: &EncryptionOptions,
    ) -> Result<EncryptionResult, Error> {
        let iv = match *options {
            EncryptionOptions::AES_CBC_HMAC_SHA { ref nonce } => nonce.to_vec(),
            ref others => return Err(unexpected_encryption_options_error!(
                AES_CBC_HMAC_SHA_ZEROED_NONCE,
                others
            )),
        };
        let aad = aad.to_vec();
        let cek = OctetKey(key.octet_key()?.to_vec());
        match self {
            ContentEncryptionAlgorithm::A128CBC_HS256 => A128CBC_HS256::encrypt(cek, payload, iv, aad),
            ContentEncryptionAlgorithm::A192CBC_HS384 => A192CBC_HS384::encrypt(cek, payload, iv, aad),
            ContentEncryptionAlgorithm::A256CBC_HS512 => A256CBC_HS512::encrypt(cek, payload, iv, aad),
            _ => Err(Error::UnsupportedOperation),
        }
    }

    pub(crate) fn aes_cbc_decrypt(
        self,
        encrypted: &EncryptionResult,
        key: &jwk::Specified,
    ) -> Result<Vec<u8>, Error> {
        let cek = OctetKey(key.octet_key()?.to_vec());
        match self {
            ContentEncryptionAlgorithm::A128CBC_HS256 => A128CBC_HS256::decrypt(cek, encrypted),
            ContentEncryptionAlgorithm::A192CBC_HS384 => A192CBC_HS384::decrypt(cek, encrypted),
            ContentEncryptionAlgorithm::A256CBC_HS512 => A256CBC_HS512::decrypt(cek, encrypted),
            _ => Err(Error::UnsupportedOperation),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aescbc_hmacsha() {
        struct Test {
            alg: ContentEncryptionAlgorithm,
            key: &'static [u8],
            enc: [u8; 144],
            tag: &'static [u8],
        }

        use hex_literal::hex;
        // from https://datatracker.ietf.org/doc/html/rfc7518#appendix-B
        let tests = [
            Test {
                alg: ContentEncryptionAlgorithm::A128CBC_HS256,
                key: &hex!(
                    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
                    "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"
                ),
                enc: hex!(
                    "c8 0e df a3 2d df 39 d5 ef 00 c0 b4 68 83 42 79"
                    "a2 e4 6a 1b 80 49 f7 92 f7 6b fe 54 b9 03 a9 c9"
                    "a9 4a c9 b4 7a d2 65 5c 5f 10 f9 ae f7 14 27 e2"
                    "fc 6f 9b 3f 39 9a 22 14 89 f1 63 62 c7 03 23 36"
                    "09 d4 5a c6 98 64 e3 32 1c f8 29 35 ac 40 96 c8"
                    "6e 13 33 14 c5 40 19 e8 ca 79 80 df a4 b9 cf 1b"
                    "38 4c 48 6f 3a 54 c5 10 78 15 8e e5 d7 9d e5 9f"
                    "bd 34 d8 48 b3 d6 95 50 a6 76 46 34 44 27 ad e5"
                    "4b 88 51 ff b5 98 f7 f8 00 74 b9 47 3c 82 e2 db"
                ),
                tag: &hex!("65 2c 3f a3 6b 0a 7c 5b 32 19 fa b3 a3 0b c1 c4"),
            },
            Test {
                alg: ContentEncryptionAlgorithm::A192CBC_HS384,
                key: &hex!(
                    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
                    "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"
                    "20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f"
                ),
                enc: hex!(
                    "ea 65 da 6b 59 e6 1e db 41 9b e6 2d 19 71 2a e5"
                    "d3 03 ee b5 00 52 d0 df d6 69 7f 77 22 4c 8e db"
                    "00 0d 27 9b dc 14 c1 07 26 54 bd 30 94 42 30 c6"
                    "57 be d4 ca 0c 9f 4a 84 66 f2 2b 22 6d 17 46 21"
                    "4b f8 cf c2 40 0a dd 9f 51 26 e4 79 66 3f c9 0b"
                    "3b ed 78 7a 2f 0f fc bf 39 04 be 2a 64 1d 5c 21"
                    "05 bf e5 91 ba e2 3b 1d 74 49 e5 32 ee f6 0a 9a"
                    "c8 bb 6c 6b 01 d3 5d 49 78 7b cd 57 ef 48 49 27"
                    "f2 80 ad c9 1a c0 c4 e7 9c 7b 11 ef c6 00 54 e3"
                ),
                tag: &hex!(
                    "84 90 ac 0e 58 94 9b fe 51 87 5d 73 3f 93 ac 20"
                    "75 16 80 39 cc c7 33 d7"
                ),
            },
            Test {
                alg: ContentEncryptionAlgorithm::A256CBC_HS512,
                key: &hex!(
                    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
                    "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"
                    "20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f"
                    "30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f"
                ),
                enc: hex!(
                    "4a ff aa ad b7 8c 31 c5 da 4b 1b 59 0d 10 ff bd"
                    "3d d8 d5 d3 02 42 35 26 91 2d a0 37 ec bc c7 bd"
                    "82 2c 30 1d d6 7c 37 3b cc b5 84 ad 3e 92 79 c2"
                    "e6 d1 2a 13 74 b7 7f 07 75 53 df 82 94 10 44 6b"
                    "36 eb d9 70 66 29 6a e6 42 7e a7 5c 2e 08 46 a1"
                    "1a 09 cc f5 37 0d c8 0b fe cb ad 28 c7 3f 09 b3"
                    "a3 b7 5e 66 2a 25 94 41 0a e4 96 b2 e2 e6 60 9e"
                    "31 e6 e0 2c c8 37 f0 53 d2 1f 37 ff 4f 51 95 0b"
                    "be 26 38 d0 9d d7 a4 93 09 30 80 6d 07 03 b1 f6"
                ),
                tag: &hex!(
                    "4d d3 b4 c0 88 a7 f4 5c 21 68 39 64 5b 20 12 bf"
                    "2e 62 69 a8 c5 6a 81 6d bc 1b 26 77 61 95 5b c5"
                ),
            },
        ];

        let payload = hex!(
            "41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20"
            "6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75"
            "69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65"
            "74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62"
            "65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69"
            "6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66"
            "20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f"
            "75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65"
        );
        let iv = hex!("1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04");
        let aad = hex!(
            "54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63"
            "69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20"
            "4b 65 72 63 6b 68 6f 66 66 73"
        );

        for test in tests {
            let key = jwk::Specified::new_octet_key(test.key);
            let opts = EncryptionOptions::AES_CBC_HMAC_SHA { nonce: iv.to_vec() };
            let res = test.alg.aes_cbc_encrypt(&payload, &aad, &key, &opts).unwrap();

            assert_eq!(res.encrypted, test.enc);
            assert_eq!(res.tag, test.tag);

            let res = test.alg.aes_cbc_decrypt(&res, &key).unwrap();

            assert_eq!(res, payload);
        }
    }
}
