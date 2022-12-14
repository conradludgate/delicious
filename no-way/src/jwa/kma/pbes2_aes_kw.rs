use aead::KeyInit;
use aes::cipher::{Block, BlockDecryptMut, BlockEncryptMut};
use aes::{Aes128, Aes192, Aes256};
use digest::core_api::BlockSizeUser;
use hmac::Hmac;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use crate::errors::Error;
use crate::jwk::OctetKey;

use super::KMA;

/// PBES2 with HMAC SHA and AES key-wrapping. [RFC7518#4.8](https://tools.ietf.org/html/rfc7518#section-4.8)
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum Pbes2Algorithm {
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    PBES2_HS256_A128KW,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    PBES2_HS384_A192KW,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    PBES2_HS512_A256KW,
}

impl From<Pbes2Algorithm> for super::Algorithm {
    fn from(p: Pbes2Algorithm) -> Self {
        super::Algorithm::Pbes2(p)
    }
}

const AES_KW_IV: u64 = 0xA6A6_A6A6_A6A6_A6A6_u64;
/// AES key wrap in-place (<https://www.rfc-editor.org/rfc/rfc3394#section-2.2.1>)
///
/// Implementation is intended for AES128/AES192/AES256 and will likely fail on any other ciphers
fn aes_key_wrap<T: BlockSizeUser + BlockEncryptMut>(mut cipher: T, out: &mut [u8]) {
    let block_size = T::block_size();

    let n = out.len() / 8 - 1;

    let mut a = AES_KW_IV;
    for j in 0..6 {
        for i in 1..=n {
            let ri = &mut out[i * 8..i * 8 + 8];

            let mut block64 = [0u64; 4];
            let block = bytemuck::cast_slice_mut(&mut block64);

            // A | R[i]
            block[..8].copy_from_slice(&a.to_be_bytes());
            block[8..16].copy_from_slice(ri);

            // B = AES(K, A | R[i])
            let block = Block::<T>::from_mut_slice(&mut block[..block_size]);
            cipher.encrypt_block_mut(block);

            // A = MSB(64, B) ^ t where t = (n*j)+i
            let t = n * j + i;
            a = block64[0].to_be() ^ t as u64;

            // R[i] = LSB(64, B)
            let lsb = block_size / 8;
            let lsb = lsb - 1..lsb;
            ri.copy_from_slice(bytemuck::cast_slice(&block64[lsb]));
        }
    }
    // Set C[0] = A
    out[..8].copy_from_slice(&a.to_be_bytes());
}

/// AES key unwrap in-place (<https://www.rfc-editor.org/rfc/rfc3394#section-2.2.2>)
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

            let mut block64 = [0u64; 4];
            let block = bytemuck::cast_slice_mut(&mut block64);

            // (A ^ t) | R[i] where t = (n*j)+i
            let t = n * j + i;
            block[..8].copy_from_slice(&(a ^ t as u64).to_be_bytes());
            block[8..16].copy_from_slice(ri);

            // B = AES-1(K, (A ^ t) | R[i])
            let block = Block::<T>::from_mut_slice(&mut block[..block_size]);
            cipher.decrypt_block_mut(block);

            // A = MSB(64, B)
            a = block64[0].to_be();

            // R[i] = LSB(64, B)
            let lsb = block_size / 8;
            let lsb = lsb - 1..lsb;
            ri.copy_from_slice(bytemuck::cast_slice(&block64[lsb]));
        }
    }
    if a != AES_KW_IV {
        return Err(Error::UnspecifiedCryptographicError);
    }
    Ok(())
}

/// Header for PBES2 algorithm.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pbes2Header {
    #[serde(rename = "p2c")]
    pub count: u32,
    #[serde(rename = "p2s")]
    pub salt: Vec<u8>,
}

macro_rules! pbes2 {
    ($id:ident, $sha:ty, $aes:ty, $key_len:expr) => {
        impl $id {
            fn kdf(key: &OctetKey, settings: &Pbes2Header) -> [u8; $key_len] {
                let name = Self::ALG.as_str();
                let mut salt = Vec::with_capacity(name.len() + 1 + settings.salt.len());
                salt.extend_from_slice(name.as_bytes());
                salt.push(0);
                salt.extend_from_slice(&settings.salt);

                let mut dk = [0; $key_len];
                pbkdf2::pbkdf2::<Hmac<$sha>>(&key.value, &salt, settings.count, &mut dk);
                dk
            }
        }

        impl KMA for $id {
            const ALG: super::Algorithm = super::Algorithm::Pbes2(Pbes2Algorithm::$id);
            type Key = OctetKey;
            type Header = Pbes2Header;
            type WrapSettings = Pbes2Header;

            fn wrap(
                cek: &[u8],
                key: &Self::Key,
                settings: Self::WrapSettings,
            ) -> Result<(Vec<u8>, Self::Header), Error> {
                let dk = Self::kdf(key, &settings);

                let len = next_multiple_of_8(cek.len());
                let mut out = vec![0; len + 8];
                out[8..][..cek.len()].copy_from_slice(cek);

                aes_key_wrap(<$aes>::new_from_slice(&dk)?, &mut out);

                Ok((out, settings))
            }

            fn unwrap<'c>(
                encrypted_cek: &'c mut [u8],
                key: &'c Self::Key,
                settings: Self::Header,
            ) -> Result<&'c [u8], Error> {
                let dk = Self::kdf(key, &settings);

                aes_key_unwrap(<$aes>::new_from_slice(&dk)?, encrypted_cek)?;

                Ok(&encrypted_cek[8..])
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

impl<Sha, Aes> Clone for Pbes2<Sha, Aes> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<Sha, Aes> Copy for Pbes2<Sha, Aes> {}

impl<Sha, Aes> PartialEq for Pbes2<Sha, Aes> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}
impl<Sha, Aes> Eq for Pbes2<Sha, Aes> {}

impl<Sha, Aes> std::fmt::Debug for Pbes2<Sha, Aes>
where
    Self: KMA,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(Self::ALG.as_str())
    }
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

pbes2!(PBES2_HS256_A128KW, sha2::Sha256, Aes128, 128 / 8);
pbes2!(PBES2_HS384_A192KW, sha2::Sha384, Aes192, 192 / 8);
pbes2!(PBES2_HS512_A256KW, sha2::Sha512, Aes256, 256 / 8);

fn next_multiple_of_8(x: usize) -> usize {
    (x + 7) & (!0b111)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // https://www.rfc-editor.org/rfc/rfc3394#section-4.1
    fn aes128_keywrapping_128() {
        let cek = hex_literal::hex!("000102030405060708090A0B0C0D0E0F");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF");

        let mut out = [0; 8 + 16];
        out[8..].copy_from_slice(&data);
        let cipher = aes::Aes128Enc::new_from_slice(&cek).unwrap();
        aes_key_wrap(cipher, &mut out);

        assert_eq!(
            out,
            hex_literal::hex!("1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5")
        );

        let cipher = aes::Aes128Dec::new_from_slice(&cek).unwrap();
        aes_key_unwrap(cipher, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    // https://www.rfc-editor.org/rfc/rfc3394#section-4.2
    fn aes192_keywrapping_128() {
        let cek = hex_literal::hex!("000102030405060708090A0B0C0D0E0F1011121314151617");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF");

        let mut out = [0; 8 + 16];
        out[8..].copy_from_slice(&data);
        let cipher = aes::Aes192Enc::new_from_slice(&cek).unwrap();
        aes_key_wrap(cipher, &mut out);

        assert_eq!(
            out,
            hex_literal::hex!("96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D")
        );

        let cipher = aes::Aes192Dec::new_from_slice(&cek).unwrap();
        aes_key_unwrap(cipher, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    // https://www.rfc-editor.org/rfc/rfc3394#section-4.3
    fn aes256_keywrapping_128() {
        let cek =
            hex_literal::hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF");

        let mut out = [0; 8 + 16];
        out[8..].copy_from_slice(&data);
        let cipher = aes::Aes256Enc::new_from_slice(&cek).unwrap();
        aes_key_wrap(cipher, &mut out);

        assert_eq!(
            out,
            hex_literal::hex!("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7")
        );

        let cipher = aes::Aes256Dec::new_from_slice(&cek).unwrap();
        aes_key_unwrap(cipher, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    // https://www.rfc-editor.org/rfc/rfc3394#section-4.4
    fn aes192_keywrapping_192() {
        let cek = hex_literal::hex!("000102030405060708090A0B0C0D0E0F1011121314151617");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF0001020304050607");

        let mut out = [0; 8 + 24];
        out[8..].copy_from_slice(&data);
        let cipher = aes::Aes192Enc::new_from_slice(&cek).unwrap();
        aes_key_wrap(cipher, &mut out);

        assert_eq!(
            out,
            hex_literal::hex!(
                "031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2"
            )
        );

        let cipher = aes::Aes192Dec::new_from_slice(&cek).unwrap();
        aes_key_unwrap(cipher, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    // https://www.rfc-editor.org/rfc/rfc3394#section-4.5
    fn aes256_keywrapping_192() {
        let cek =
            hex_literal::hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let data = hex_literal::hex!("00112233445566778899AABBCCDDEEFF0001020304050607");

        let mut out = [0; 8 + 24];
        out[8..].copy_from_slice(&data);
        let cipher = aes::Aes256Enc::new_from_slice(&cek).unwrap();
        aes_key_wrap(cipher, &mut out);

        assert_eq!(
            out,
            hex_literal::hex!(
                "A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1"
            )
        );

        let cipher = aes::Aes256Dec::new_from_slice(&cek).unwrap();
        aes_key_unwrap(cipher, &mut out).unwrap();

        assert_eq!(out[8..], data);
    }

    #[test]
    // https://www.rfc-editor.org/rfc/rfc3394#section-4.6
    fn aes256_keywrapping_256() {
        let cek =
            hex_literal::hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let data =
            hex_literal::hex!("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");

        let mut out = [0; 8 + 32];
        out[8..].copy_from_slice(&data);
        let cipher = aes::Aes256Enc::new_from_slice(&cek).unwrap();
        aes_key_wrap(cipher, &mut out);

        assert_eq!(
            out,
            hex_literal::hex!(
                "28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326
            CBC7F0E71A99F43B FB988B9B7A02DD21"
            )
        );

        let cipher = aes::Aes256Dec::new_from_slice(&cek).unwrap();
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
        let key = OctetKey::new(b"Thus from my lips, by yours, my sin is purged.".to_vec());
        let header = Pbes2Header {
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

        kma_round_trip::<PBES2_HS256_A128KW>(&payload, &key, header, &expected);
    }

    fn kma_round_trip<K: KMA>(
        payload: &[u8],
        key: &K::Key,
        settings: K::WrapSettings,
        expected: &[u8],
    ) {
        let (mut encrypted_cek, header) = K::wrap(payload, key, settings).unwrap();
        assert_eq!(encrypted_cek, expected);

        let decrypted_cek = K::unwrap(&mut encrypted_cek, key, header).unwrap();
        assert_eq!(decrypted_cek, payload);
    }
}
