use std::fmt;

use super::BigUint;
use base64ct::Encoding;

impl BigUint {
    /// Parses a big-endian base64 encoded string into a bigint
    pub fn from_base64_be(s: &str) -> Result<Self, base64ct::Error> {
        let len = s.len() / 4 * 3 + 3;
        let quads = (len + 3) / 4; // ceil divide
        let mut data = vec![0u32; quads];

        let bytes = bytemuck::cast_slice_mut(&mut data);
        let n = crate::B64::decode(s, bytes)?.len();

        // safety: n is within the size of data
        unsafe { Ok(Self::from_be_bytes_u32(data, n)) }
    }

    /// Encodes the bigint into a big-endian base64 encoded string
    pub fn as_base64_be(&self) -> BigUintBase64Be<'_> {
        BigUintBase64Be(&self.data)
    }

    pub fn to_base64_be(&self) -> String {
        self.as_base64_be().to_string()
    }
}

pub struct BigUintBase64Be<'a>(&'a [u32]);

impl fmt::Display for BigUintBase64Be<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let last = match self.0.last() {
            Some(last) => *last,
            None => return Ok(()),
        };
        let offset = (last.leading_zeros() / 8) as usize;

        // 3 chunks (12 bytes) turns into 16 bytes of output.
        let mut buf = [0; 16];
        let mut chunks = [0; 4];

        let mut i = self.0.len();

        // Work on chunks of 3 (12 bytes) at a time since it fits nicely with our
        // base64 output. We actually make sure to have 4 chunks available since we might need to
        // offset a few bytes
        while i >= 4 {
            let j = i - 4;
            chunks.copy_from_slice(&self.0[j..i]);
            i -= 3;

            chunks.reverse();
            for chunk in &mut chunks {
                *chunk = chunk.to_be();
            }

            let bytes = bytemuck::cast_slice::<u32, u8>(&chunks);
            let bytes = unsafe { bytes.get_unchecked(offset..12 + offset) };
            let s = crate::B64::encode(bytes, &mut buf).unwrap();
            f.write_str(s)?;
        }

        // deal with the remaining bytes
        {
            let chunks = &mut chunks[..i];
            chunks.copy_from_slice(&self.0[..i]);

            chunks.reverse();
            for i in &mut *chunks {
                *i = i.to_be();
            }

            let bytes = bytemuck::cast_slice::<u32, u8>(chunks);
            let bytes = unsafe { bytes.get_unchecked(offset..4 * i) };
            let s = crate::B64::encode(bytes, &mut buf).unwrap();
            f.write_str(s)?;
        }

        Ok(())
    }
}

impl From<u32> for BigUint {
    fn from(x: u32) -> Self {
        if x == 0 {
            Self::zero()
        } else {
            Self { data: vec![x] }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use base64ct::Encoding;
    use serde_test::{assert_tokens, Token};

    use super::BigUint;

    #[test]
    fn from_base64_be_small() {
        let bi = BigUint::from_base64_be("MDk").unwrap();
        assert_eq!(bi, BigUint::from(12345));
    }
    #[test]
    fn from_base64_be_big() {
        let bi = BigUint::from_base64_be("mHZUMhA").unwrap();
        assert_eq!(bi, BigUint::new(vec![0x7654_3210, 0x98]));
    }

    #[test]
    fn as_base64_be_small() {
        assert_eq!(BigUint::from(12345).as_base64_be().to_string(), "MDk");
    }
    #[test]
    fn as_base64_be_big() {
        assert_eq!(
            BigUint::new(vec![0x7654_3210, 0xfedc_ba98, 0x7654_3210, 0xba98])
                .as_base64_be()
                .to_string(),
            "uph2VDIQ_ty6mHZUMhA"
        );
    }

    #[test]
    fn some_serialization_round_trip() {
        let test_value = Some(BigUint::from(12345));

        assert_tokens(&test_value, &[Token::Some, Token::Str("MDk")]);
    }

    #[test]
    fn none_serialization_round_trip() {
        let test_value = None::<BigUint>;

        assert_tokens(&test_value, &[Token::None]);
    }

    #[test]
    fn some_json_serialization_round_trip() {
        let test_value = Some(BigUint::from(12345));
        let expected_json = r#""MDk""#;

        let actual_json = serde_json::to_string(&test_value).unwrap();
        assert_eq!(expected_json, actual_json);

        let deserialized_value: Option<BigUint> = serde_json::from_str(&actual_json).unwrap();
        assert_eq!(test_value, deserialized_value);
    }

    #[test]
    fn none_json_serialization_round_trip() {
        let test_value = None::<BigUint>;
        let expected_json = r#"null"#;

        let actual_json = serde_json::to_string(&test_value).unwrap();
        assert_eq!(expected_json, actual_json);

        let deserialized_value: Option<BigUint> = serde_json::from_str(&actual_json).unwrap();
        assert_eq!(test_value, deserialized_value);
    }

    #[test]
    fn base64_very_long() {
        let s = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        let bytes = crate::B64::decode_vec(s).unwrap();
        let a = BigUint::from_be_bytes(&bytes);
        let b = BigUint::from_base64_be(s).unwrap();
        assert_eq!(a, b);

        let bytes2 = a.to_be_bytes();
        assert_eq!(bytes, bytes2);

        let c = BigUint::new(vec![
            2661337731, 446995658, 1209332140, 183172752, 955894533, 3140848734, 581365968,
            3217299938, 3520742369, 1559833632, 1548159735, 2303031139, 1726816051, 92775838,
            37272772, 1817499268, 2876656510, 1328166076, 2779910671, 4258539214, 2834014041,
            3172137349, 4008354576, 121660540, 1941402830, 1620936445, 993798294, 47616683,
            272681116, 983097263, 225284287, 3494334405, 4005126248, 1126447551, 2189379704,
            4098746126, 3730484719, 3232696701, 2583545877, 428738419, 2533069420, 2922211325,
            2227907999, 4154608099, 679827337, 1165541732, 2407118218, 3485541440, 799756961,
            1854157941, 3062830172, 3270332715, 1431293619, 3068067851, 2238478449, 2704523019,
            2826966453, 1548381401, 3719104923, 2605577849, 2293389158, 273345423, 169765991,
            3539762026,
        ]);
        assert_eq!(a, c);

        assert_eq!(c.as_base64_be().to_string(), s);
    }

    fn add(a: Vec<u32>, b: Vec<u32>) -> BigUint {
        let a = BigUint::new(a);
        let b = BigUint::new(b);
        let c = a.clone() + &b;
        let d = b + &a;
        assert_eq!(c, d);
        c
    }

    #[test]
    fn add_same_size() {
        let c = add(vec![u32::MAX], vec![2]);
        assert_eq!(c, BigUint::new(vec![1, 1]));
    }

    #[test]
    fn add_multiple_carry() {
        let c = add(vec![u32::MAX, u32::MAX, 1, u32::MAX], vec![2]);
        assert_eq!(c, BigUint::new(vec![1, 0, 2, u32::MAX]));
    }
}
