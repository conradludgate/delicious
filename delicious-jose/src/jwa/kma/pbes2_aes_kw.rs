use aes::cipher::{Block, BlockDecryptMut, BlockEncryptMut};
use aes::{Aes128, Aes192, Aes256};
use cipher::BlockSizeUser;
use cipher::KeyInit;
use std::num::NonZeroU32;

use crate::errors::Error;
use crate::jwk;
use crate::Empty;

/// Algorithms for key management as defined in [RFC7518#4.8](https://tools.ietf.org/html/rfc7518#section-4.8)
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum KMA_PBES2 {
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    HS256_A128KW,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    HS384_A192KW,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    HS512_A256KW,
}

/// Algorithms for key management as defined in [RFC7518#4.8](https://tools.ietf.org/html/rfc7518#section-4.8)
#[allow(non_camel_case_types)]
pub struct PBES2 {
    pub kma: KMA_PBES2,
    pub salt: String,
    pub count: u32,
}

impl PBES2 {
    pub fn encrypt(self, payload: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
        use KMA_PBES2::{
            HS256_A128KW, HS384_A192KW, HS512_A256KW,
        };

        use ring::pbkdf2;
        let alg = match self.kma {
            HS256_A128KW => pbkdf2::PBKDF2_HMAC_SHA256,
            HS384_A192KW => pbkdf2::PBKDF2_HMAC_SHA384,
            HS512_A256KW => pbkdf2::PBKDF2_HMAC_SHA512,
        };
        let len = match self.kma {
            HS256_A128KW => 128 / 8,
            HS384_A192KW => 192 / 8,
            HS512_A256KW => 256 / 8,
        };
        let count = NonZeroU32::new(self.count).ok_or(Error::UnspecifiedCryptographicError)?;

        // compute salt
        let mut salt = match self.kma {
            HS256_A128KW => b"PBES2-HS256+A128KW".to_vec(),
            HS384_A192KW => b"PBES2-HS384+A192KW".to_vec(),
            HS512_A256KW => b"PBES2-HS512+A256KW".to_vec(),
        };
        salt.push(0);
        base64::decode_config_buf(self.salt, base64::URL_SAFE_NO_PAD, &mut salt)?;

        let mut dk = [0; 32];
        pbkdf2::derive(alg, count, &salt, key, &mut dk[..len]);

        let len = (payload.len() + 7) / 8;
        let mut out = vec![0; len * 8 + 8];
        out[8..][..payload.len()].copy_from_slice(payload);

        match self.kma {
            HS256_A128KW => aes_key_wrap(Aes128::new_from_slice(&dk[..16])?, &mut out),
            HS384_A192KW => aes_key_wrap(Aes192::new_from_slice(&dk[..24])?, &mut out),
            HS512_A256KW => aes_key_wrap(Aes256::new_from_slice(&dk)?, &mut out),
        }

        Ok(out)
    }

    pub fn decrypt(self, encrypted: &[u8], key: &[u8]) -> Result<jwk::JWK<Empty>, Error> {
        use KMA_PBES2::{
            HS256_A128KW, HS384_A192KW, HS512_A256KW,
        };

        use ring::pbkdf2;
        let alg = match self.kma {
            HS256_A128KW => pbkdf2::PBKDF2_HMAC_SHA256,
            HS384_A192KW => pbkdf2::PBKDF2_HMAC_SHA384,
            HS512_A256KW => pbkdf2::PBKDF2_HMAC_SHA512,
        };
        let len = match self.kma {
            HS256_A128KW => 128 / 8,
            HS384_A192KW => 192 / 8,
            HS512_A256KW => 256 / 8,
        };
        let count = NonZeroU32::new(self.count).ok_or(Error::UnspecifiedCryptographicError)?;

        // compute salt
        let mut salt = match self.kma {
            HS256_A128KW => b"PBES2-HS256+A128KW".to_vec(),
            HS384_A192KW => b"PBES2-HS384+A192KW".to_vec(),
            HS512_A256KW => b"PBES2-HS512+A256KW".to_vec(),
        };
        salt.push(0);
        base64::decode_config_buf(self.salt, base64::URL_SAFE_NO_PAD, &mut salt)?;

        let mut dk = [0; 32];
        pbkdf2::derive(alg, count, &salt, key, &mut dk[..len]);

        dbg!(&dk);

        let len = (encrypted.len() + 7) / 8;
        let mut out = vec![0; len * 8 + 8];
        out[8..][..encrypted.len()].copy_from_slice(encrypted);

        match self.kma {
            HS256_A128KW => aes_key_unwrap(Aes128::new_from_slice(&dk[..16])?, &mut out)?,
            HS384_A192KW => aes_key_unwrap(Aes192::new_from_slice(&dk[..24])?, &mut out)?,
            HS512_A256KW => aes_key_unwrap(Aes256::new_from_slice(&dk)?, &mut out)?,
        }

        Ok(jwk::JWK {
            algorithm: jwk::AlgorithmParameters::OctetKey(jwk::OctetKeyParameters {
                value: out,
                key_type: Default::default(),
            }),
            common: jwk::CommonParameters {
                public_key_use: Some(jwk::PublicKeyUse::Encryption),
                algorithm: None,
                ..Default::default()
            },
            additional: Default::default(),
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
        let cek = PBES2 {
            kma: KMA_PBES2::HS256_A128KW,
            salt,
            count: 4096,
        }
        .encrypt(&payload, key)
        .unwrap();

        assert_eq!(
            cek,
            [
                78, 186, 151, 59, 11, 141, 81, 240, 213, 245, 83, 211, 53, 188, 134, 188, 66, 125,
                36, 200, 222, 124, 5, 103, 249, 52, 117, 184, 140, 81, 246, 158, 161, 177, 20, 33,
                245, 57, 59, 4
            ]
        )
    }
}
