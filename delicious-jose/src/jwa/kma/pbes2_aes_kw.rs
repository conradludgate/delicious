use aead::KeyInit;
use aes::cipher::{Block, BlockDecryptMut, BlockEncryptMut};
use aes::{Aes128, Aes192, Aes256};
use digest::core_api::BlockSizeUser;
use hmac::Hmac;
use std::marker::PhantomData;

use crate::errors::Error;
use crate::jwa::OctetKey;

use super::KMA;

/// PBES2 with HMAC SHA and AES key-wrapping. [RFC7518#4.8](https://tools.ietf.org/html/rfc7518#section-4.8)
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum PBES2 {
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    HS256_A128KW,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    HS384_A192KW,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    HS512_A256KW,
}

impl From<PBES2> for super::Algorithm {
    fn from(p: PBES2) -> Self {
        super::Algorithm::PBES2(p)
    }
}

impl PBES2 {
    pub fn encrypt(
        self,
        payload: &[u8],
        key: &[u8],
        salt: &str,
        count: u32,
    ) -> Result<Vec<u8>, Error> {
        use PBES2::{HS256_A128KW, HS384_A192KW, HS512_A256KW};

        let cek = OctetKey(payload.to_vec());
        let key = OctetKey(key.to_vec());
        let header = PBES2_Header {
            count,
            salt: base64::decode_config(salt, base64::URL_SAFE_NO_PAD)?,
        };
        Ok(match self {
            HS256_A128KW => PBES2_HS256_A128KW::wrap(cek, &key, header)?.0,
            HS384_A192KW => PBES2_HS384_A192KW::wrap(cek, &key, header)?.0,
            HS512_A256KW => PBES2_HS512_A256KW::wrap(cek, &key, header)?.0,
        })
    }

    pub fn decrypt(
        self,
        encrypted: &[u8],
        key: &[u8],
        salt: &str,
        count: u32,
    ) -> Result<Vec<u8>, Error> {
        use PBES2::{HS256_A128KW, HS384_A192KW, HS512_A256KW};

        let key = OctetKey(key.to_vec());
        let header = PBES2_Header {
            count,
            salt: base64::decode_config(salt, base64::URL_SAFE_NO_PAD)?,
        };
        Ok(match self {
            HS256_A128KW => PBES2_HS256_A128KW::unwrap(encrypted, &key, header)?.0,
            HS384_A192KW => PBES2_HS384_A192KW::unwrap(encrypted, &key, header)?.0,
            HS512_A256KW => PBES2_HS512_A256KW::unwrap(encrypted, &key, header)?.0,
        })
    }
}

const AES_KW_IV: u64 = 0xA6A6A6A6A6A6A6A6_u64;
/// AES key wrap in-place (https://www.rfc-editor.org/rfc/rfc3394#section-2.2.1)
///
/// Implementation is intended for AES128/AES192/AES256 and will likely fail on any other ciphers
fn aes_key_wrap<T: BlockSizeUser + BlockEncryptMut>(mut cipher: T, out: &mut [u8]) {
    let block_size = T::block_size();

    let n = out.len() / 8 - 1;

    let mut a = AES_KW_IV;
    for j in 0..6 {
        for i in 1..=n {
            let ri = &mut out[i * 8..i * 8 + 8];

            // A | R[i]
            let mut input = [0; 32];
            input[..8].copy_from_slice(&a.to_be_bytes());
            input[8..16].copy_from_slice(ri);

            let mut out2 = [0u64; 4];
            let out_block = bytemuck::cast_slice_mut(&mut out2);

            // B = AES(K, A | R[i])
            let in_block = Block::<T>::from_slice(&input[..block_size]);
            let out_block = Block::<T>::from_mut_slice(&mut out_block[..block_size]);
            cipher.encrypt_block_b2b_mut(in_block, out_block);

            // A = MSB(64, B) ^ t where t = (n*j)+i
            let t = n * j + i;
            a = out2[0].to_be() ^ t as u64;

            // R[i] = LSB(64, B)
            let lsb = block_size / 8;
            let lsb = lsb - 1..lsb;
            ri.copy_from_slice(bytemuck::cast_slice(&out2[lsb]))
        }
    }
    // Set C[0] = A
    out[..8].copy_from_slice(&a.to_be_bytes());
}

/// AES key unwrap in-place (https://www.rfc-editor.org/rfc/rfc3394#section-2.2.2)
///
/// Implementation is intended for AES128/AES192/AES256 and will likely fail on any other ciphers
fn aes_key_unwrap<T: BlockSizeUser + BlockDecryptMut>(
    mut cipher: T,
    out: &mut [u8],
) -> Result<(), Error> {
    let block_size = T::block_size();

    let n = out.len() / 8 - 1;

    let mut a = u64::from_be_bytes(out[..8].try_into().unwrap());
    for j in (0..6).rev() {
        for i in (1..=n).rev() {
            let ri = &mut out[i * 8..i * 8 + 8];

            // (A ^ t) | R[i] where t = (n*j)+i
            let mut input = [0; 32];
            let t = n * j + i;
            input[..8].copy_from_slice(&(a ^ t as u64).to_be_bytes());
            input[8..16].copy_from_slice(ri);

            let mut out2 = [0u64; 4];
            let out_block = bytemuck::cast_slice_mut(&mut out2);

            // B = AES-1(K, (A ^ t) | R[i])
            let in_block = Block::<T>::from_slice(&input[..block_size]);
            let out_block2 = Block::<T>::from_mut_slice(&mut out_block[..block_size]);
            cipher.decrypt_block_b2b_mut(in_block, out_block2);

            // A = MSB(64, B)
            a = out2[0].to_be();

            // R[i] = LSB(64, B)
            let lsb = block_size / 8;
            let lsb = lsb - 1..lsb;
            ri.copy_from_slice(bytemuck::cast_slice(&out2[lsb]))
        }
    }
    if a != AES_KW_IV {
        return Err(Error::UnspecifiedCryptographicError);
    }
    Ok(())
}

#[allow(non_camel_case_types)]
pub struct PBES2_Header {
    count: u32,
    salt: Vec<u8>,
}

macro_rules! pbes2 {
    ($id:ident, $sha:ty, $aes:ty, $name:literal, $key_len:expr) => {
        impl KMA for $id {
            const ALG: &'static str = $name;
            type Key = OctetKey;
            type Cek = OctetKey;
            type AlgorithmHeader = PBES2_Header;
            type WrapSettings = PBES2_Header;

            fn wrap(
                cek: Self::Cek,
                key: &Self::Key,
                settings: Self::WrapSettings,
            ) -> Result<(Vec<u8>, Self::AlgorithmHeader), Error> {
                let mut salt = Vec::with_capacity($name.len() + 1 + settings.salt.len());
                salt.extend_from_slice($name.as_bytes());
                salt.push(0);
                salt.extend_from_slice(&settings.salt);

                let mut dk = [0; $key_len];
                pbkdf2::pbkdf2::<Hmac<$sha>>(&key.0, &salt, settings.count, &mut dk);

                let payload = &cek.0;
                let len = next_multiple_of_8(payload.len());
                let mut out = vec![0; len + 8];
                out[8..][..payload.len()].copy_from_slice(payload);

                aes_key_wrap(<$aes>::new_from_slice(&dk)?, &mut out);

                Ok((out, settings))
            }

            fn unwrap(
                encrypted_cek: &[u8],
                key: &Self::Key,
                settings: Self::AlgorithmHeader,
            ) -> Result<Self::Cek, Error> {
                let mut salt = Vec::with_capacity($name.len() + 1 + settings.salt.len());
                salt.extend_from_slice($name.as_bytes());
                salt.push(0);
                salt.extend_from_slice(&settings.salt);

                let mut dk = [0; $key_len];
                pbkdf2::pbkdf2::<Hmac<$sha>>(&key.0, &salt, settings.count, &mut dk);

                let len = next_multiple_of_8(encrypted_cek.len());
                let mut out = vec![0; len];
                out[..encrypted_cek.len()].copy_from_slice(encrypted_cek);

                aes_key_unwrap(<$aes>::new_from_slice(&dk)?, &mut out)?;

                out.rotate_left(8);
                out.truncate(len - 8);

                Ok(OctetKey(out))
            }
        }
    };
}

#[allow(non_camel_case_types)]
/// [Key Encryption with PBES2](https://datatracker.ietf.org/doc/html/rfc7518#section-4.8)
///
/// See
/// * [`PBES2_HS256_A128KW`] - PBES2 key management algorithm using SHA256 and AES128
/// * [`PBES2_HS384_A192KW`] - PBES2 key management algorithm using SHA384 and AES192
/// * [`PBES2_HS512_A256KW`] - PBES2 key management algorithm using SHA512 and AES256
pub struct Pbes2<Sha, Aes> {
    _sha: PhantomData<Sha>,
    _aes: PhantomData<Aes>,
}

#[allow(non_camel_case_types)]
/// PBES2 key management algorithm using SHA256 and AES128
pub type PBES2_HS256_A128KW = Pbes2<sha2::Sha256, Aes128>;
#[allow(non_camel_case_types)]
/// PBES2 key management algorithm using SHA384 and AES192
pub type PBES2_HS384_A192KW = Pbes2<sha2::Sha384, Aes192>;
#[allow(non_camel_case_types)]
/// PBES2 key management algorithm using SHA512 and AES256
pub type PBES2_HS512_A256KW = Pbes2<sha2::Sha512, Aes256>;

pbes2!(
    PBES2_HS256_A128KW,
    sha2::Sha256,
    Aes128,
    "PBES2-HS256+A128KW",
    128 / 8
);
pbes2!(
    PBES2_HS384_A192KW,
    sha2::Sha384,
    Aes192,
    "PBES2-HS384+A192KW",
    192 / 8
);
pbes2!(
    PBES2_HS512_A256KW,
    sha2::Sha512,
    Aes256,
    "PBES2-HS512+A256KW",
    256 / 8
);

fn next_multiple_of_8(x: usize) -> usize {
    (x + 7) & (!0b111)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // https://www.rfc-editor.org/rfc/rfc3394#section-4.1
    fn aes128_keywrapping_128() {
        let kek = hex_literal::hex!("000102030405060708090A0B0C0D0E0F");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF");

        let mut out = [0; 8 + 16];
        out[8..].copy_from_slice(&data);
        let cipher = aes::Aes128Enc::new_from_slice(&kek).unwrap();
        aes_key_wrap(cipher, &mut out);

        assert_eq!(
            out,
            hex_literal::hex!("1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5")
        );

        let cipher = aes::Aes128Dec::new_from_slice(&kek).unwrap();
        aes_key_unwrap(cipher, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    // https://www.rfc-editor.org/rfc/rfc3394#section-4.2
    fn aes192_keywrapping_128() {
        let kek = hex_literal::hex!("000102030405060708090A0B0C0D0E0F1011121314151617");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF");

        let mut out = [0; 8 + 16];
        out[8..].copy_from_slice(&data);
        let cipher = aes::Aes192Enc::new_from_slice(&kek).unwrap();
        aes_key_wrap(cipher, &mut out);

        assert_eq!(
            out,
            hex_literal::hex!("96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D")
        );

        let cipher = aes::Aes192Dec::new_from_slice(&kek).unwrap();
        aes_key_unwrap(cipher, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    // https://www.rfc-editor.org/rfc/rfc3394#section-4.3
    fn aes256_keywrapping_128() {
        let kek =
            hex_literal::hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF");

        let mut out = [0; 8 + 16];
        out[8..].copy_from_slice(&data);
        let cipher = aes::Aes256Enc::new_from_slice(&kek).unwrap();
        aes_key_wrap(cipher, &mut out);

        assert_eq!(
            out,
            hex_literal::hex!("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7")
        );

        let cipher = aes::Aes256Dec::new_from_slice(&kek).unwrap();
        aes_key_unwrap(cipher, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    // https://www.rfc-editor.org/rfc/rfc3394#section-4.4
    fn aes192_keywrapping_192() {
        let kek = hex_literal::hex!("000102030405060708090A0B0C0D0E0F1011121314151617");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF0001020304050607");

        let mut out = [0; 8 + 24];
        out[8..].copy_from_slice(&data);
        let cipher = aes::Aes192Enc::new_from_slice(&kek).unwrap();
        aes_key_wrap(cipher, &mut out);

        assert_eq!(
            out,
            hex_literal::hex!(
                "031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2"
            )
        );

        let cipher = aes::Aes192Dec::new_from_slice(&kek).unwrap();
        aes_key_unwrap(cipher, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    // https://www.rfc-editor.org/rfc/rfc3394#section-4.5
    fn aes256_keywrapping_192() {
        let kek =
            hex_literal::hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF0001020304050607");

        let mut out = [0; 8 + 24];
        out[8..].copy_from_slice(&data);
        let cipher = aes::Aes256Enc::new_from_slice(&kek).unwrap();
        aes_key_wrap(cipher, &mut out);

        assert_eq!(
            out,
            hex_literal::hex!(
                "A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1"
            )
        );

        let cipher = aes::Aes256Dec::new_from_slice(&kek).unwrap();
        aes_key_unwrap(cipher, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    // https://www.rfc-editor.org/rfc/rfc3394#section-4.6
    fn aes256_keywrapping_256() {
        let kek =
            hex_literal::hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let data =
            hex_literal::hex!("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");

        let mut out = [0; 8 + 32];
        out[8..].copy_from_slice(&data);
        let cipher = aes::Aes256Enc::new_from_slice(&kek).unwrap();
        aes_key_wrap(cipher, &mut out);

        assert_eq!(
            out,
            hex_literal::hex!(
                "28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326
            CBC7F0E71A99F43B FB988B9B7A02DD21"
            )
        );

        let cipher = aes::Aes256Dec::new_from_slice(&kek).unwrap();
        aes_key_unwrap(cipher, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    // https://www.rfc-editor.org/rfc/rfc7517.html#appendix-C.2
    fn pbes2_hs256_a128kw() {
        let payload = [
            111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55,
            202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182,
        ];
        let key = b"Thus from my lips, by yours, my sin is purged.";
        let salt = base64::encode_config(
            [
                217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215,
            ],
            base64::URL_SAFE_NO_PAD,
        );
        let encrypted_cek = PBES2::HS256_A128KW
            .encrypt(&payload, key, &salt, 4096)
            .unwrap();

        assert_eq!(
            encrypted_cek,
            [
                78, 186, 151, 59, 11, 141, 81, 240, 213, 245, 83, 211, 53, 188, 134, 188, 66, 125,
                36, 200, 222, 124, 5, 103, 249, 52, 117, 184, 140, 81, 246, 158, 161, 177, 20, 33,
                245, 57, 59, 4
            ]
        );

        let decrypted_cek = PBES2::HS256_A128KW
            .decrypt(&encrypted_cek, key, &salt, 4096)
            .unwrap();

        assert_eq!(decrypted_cek, payload);
    }

    #[test]
    // https://www.rfc-editor.org/rfc/rfc7517.html#appendix-C.2
    fn pbes2_hs256_a128kw_generic() {
        let payload = OctetKey(
            [
                111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36,
                55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182,
            ]
            .to_vec(),
        );
        let key = OctetKey(b"Thus from my lips, by yours, my sin is purged.".to_vec());
        let header = PBES2_Header {
            count: 4096,
            salt: vec![
                217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215,
            ],
        };
        let expected = [
            78, 186, 151, 59, 11, 141, 81, 240, 213, 245, 83, 211, 53, 188, 134, 188, 66, 125, 36,
            200, 222, 124, 5, 103, 249, 52, 117, 184, 140, 81, 246, 158, 161, 177, 20, 33, 245, 57,
            59, 4,
        ];

        kma_round_trip::<PBES2_HS256_A128KW>(payload, &key, header, &expected);
    }

    fn kma_round_trip<K: KMA>(
        payload: K::Cek,
        key: &K::Key,
        settings: K::WrapSettings,
        expected: &[u8],
    ) where
        K::Cek: Clone + PartialEq + std::fmt::Debug,
    {
        let (encrypted_cek, header) = K::wrap(payload.clone(), key, settings).unwrap();

        assert_eq!(encrypted_cek, expected);

        let decrypted_cek = K::unwrap(&encrypted_cek, key, header).unwrap();

        assert_eq!(decrypted_cek, payload);
    }
}
