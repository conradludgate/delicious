use std::{
    fmt,
    ops::{Add, AddAssign},
};

use base64ct::Encoding;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BigUint {
    /// data stored as little endian u32 (the least significant u32 chunks are at the start of the array).
    /// The bytes within the u32 are stored native endian.
    ///
    /// Eg u32::MAX + 1 would be stored as vec![0, 1]
    data: Vec<u32>,
}

impl BigUint {
    pub const fn zero() -> Self {
        Self { data: Vec::new() }
    }
    /// Create a new bigint with little endian u32 chunks
    pub fn new(data: Vec<u32>) -> Self {
        Self { data }
    }

    /// Parses a big-endian base64 encoded string into a bigint
    fn from_be_bytes_u32(mut data: Vec<u32>, full_bytes: usize) -> Self {
        #[cfg(target_endian = "little")]
        {
            // the chunks and the u32 bytes need reversing.
            // reversing all bytes has that effect
            bytemuck::cast_slice_mut::<u32, u8>(&mut data)[..full_bytes].reverse();
            data.truncate((full_bytes + 3) / 4);
        }
        #[cfg(not(target_endian = "little"))]
        {
            // only the chunks need reversing into little endian.
            // u32 bytes are big-endian natively so they can remain
            data.truncate((full_bytes + 3) / 4);
            data.reverse();
        }

        Self { data }
    }

    /// Create a new `BigUint` from big endian bytes
    pub fn from_be_bytes(b: &[u8]) -> Self {
        let mut data = vec![0u32; (b.len() + 3) / 4];

        bytemuck::cast_slice_mut(&mut data)[..b.len()].copy_from_slice(b);

        Self::from_be_bytes_u32(data, b.len())
    }

    /// Parses a big-endian base64 encoded string into a bigint
    pub fn from_base64_be(s: &str) -> Result<Self, base64ct::Error> {
        let len = s.len() / 4 * 3 + 3;
        let quads = (len + 3) / 4; // ceil divide
        let mut data = vec![0u32; quads];

        let bytes = bytemuck::cast_slice_mut(&mut data);
        let n = crate::B64::decode(s, bytes)?.len();

        Ok(Self::from_be_bytes_u32(data, n))
    }

    /// Extract the big endian bytes from this `BigUint`
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut output =Vec::with_capacity(self.data.len() * 4);
        let mut iter = self.data.iter();
        if let Some(last) = iter.next_back() {
            let offset = last.leading_zeros() / 8;
            output.extend_from_slice(&last.to_be_bytes()[offset as usize..]);
            for chunk in iter.rev() {
                output.extend_from_slice(&chunk.to_be_bytes());
            }
        }
        output
    }

    /// Encodes the bigint into a big-endian base64 encoded string
    pub fn as_base64_be(&self) -> BigUintBase64Be<'_> {
        BigUintBase64Be(&self.data)
    }
}

pub struct BigUintBase64Be<'a>(&'a [u32]);

impl Serialize for BigUintBase64Be<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

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

            chunks.reverse();
            for i in &mut chunks {
                *i = i.to_be();
            }

            let bytes = &bytemuck::cast_slice_mut::<u32, u8>(&mut chunks)[offset..12 + offset];
            let s = crate::B64::encode(bytes, &mut buf).unwrap();
            f.write_str(s)?;

            i -= 3;
        }

        // deal with the remaining bytes
        {
            let chunks = &mut chunks[..i];
            chunks.copy_from_slice(&self.0[..i]);

            chunks.reverse();
            for i in &mut *chunks {
                *i = i.to_be();
            }

            let bytes = &bytemuck::cast_slice_mut::<u32, u8>(chunks)[offset..4 * i];
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

// from u32::carrying_add on nightly
const fn carrying_add(lhs: u32, rhs: u32, carry: bool) -> (u32, bool) {
    let (a, b) = lhs.overflowing_add(rhs);
    let (c, d) = a.overflowing_add(carry as u32);
    (c, b || d)
}

/// Two argument addition of raw slices, `a += b`, returning the carry.
///
/// This is used when the data `Vec` might need to resize to push a non-zero carry, so we perform
/// the addition first hoping that it will fit.
///
/// Safety:
/// The caller _must_ ensure that `a` is at least as long as `b`.
#[inline]
unsafe fn add2(a: &mut [u32], b: &[u32]) -> bool {
    debug_assert!(a.len() >= b.len());

    let mut carry = false;
    let (a_lo, a_hi) = a.split_at_mut(b.len());

    for (a, b) in a_lo.iter_mut().zip(b) {
        (*a, carry) = carrying_add(*a, *b, carry);
    }

    add_carry(a_hi, carry)
}

#[inline]
fn add_carry(mut a: &mut [u32], mut carry: bool) -> bool {
    while carry {
        match a.split_first_mut() {
            Some((x, a1)) => {
                a = a1;
                (*x, carry) = carrying_add(*x, 0, carry);
            }
            None => return true,
        }
    }
    false
}

impl AddAssign<&'_ BigUint> for BigUint {
    #[inline]
    fn add_assign(&mut self, other: &BigUint) {
        let self_len = self.data.len();
        let carry = if self_len < other.data.len() {
            let (lo, hi) = other.data.split_at(self_len);

            // add the hi chunks first
            self.data.extend_from_slice(hi);

            // add the low chunks with carry
            // safety: self.data is longer than lo
            unsafe { add2(&mut self.data, lo) }
        } else {
            // safety: we've checked that self_len >= other.len()
            unsafe { add2(&mut self.data, &other.data) }
        };
        if carry {
            self.data.push(1);
        }
    }
}

impl Add<&'_ BigUint> for BigUint {
    type Output = BigUint;

    fn add(mut self, other: &BigUint) -> BigUint {
        self += other;
        self
    }
}

impl AddAssign<u32> for BigUint {
    #[inline]
    fn add_assign(&mut self, other: u32) {
        if other != 0 {
            if self.data.is_empty() {
                self.data.push(other);
            } else {
                // safety: self.data has at least 1 value
                let carry = unsafe { add2(&mut self.data, &[other]) };
                if carry {
                    self.data.push(1);
                }
            }
        }
    }
}

impl Add<u32> for BigUint {
    type Output = BigUint;

    #[inline]
    fn add(mut self, other: u32) -> BigUint {
        self += other;
        self
    }
}

mod serde_impls {
    use super::BigUint;
    use serde::{de, Deserialize, Serialize};
    use std::fmt;

    /// Serialize a `BigUInt` as a base64 encoded big-endian string
    impl Serialize for BigUint {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.collect_str(&self.as_base64_be())
        }
    }

    impl<'de> Deserialize<'de> for BigUint {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct BigUintVisitor;

            impl<'de> de::Visitor<'de> for BigUintVisitor {
                type Value = BigUint;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("a Base64urlUInt string")
                }

                fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    BigUint::from_base64_be(value).map_err(E::custom)
                }
            }

            deserializer.deserialize_str(BigUintVisitor)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use base64ct::Encoding;
    use serde::{Deserialize, Serialize};
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

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
    struct TestStruct {
        bytes: Option<BigUint>,
    }

    #[test]
    fn some_serialization_round_trip() {
        let test_value = TestStruct {
            bytes: Some(BigUint::from(12345)),
        };

        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "TestStruct",
                    len: 1,
                },
                Token::Str("bytes"),
                Token::Some,
                Token::Str("MDk"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn none_serialization_round_trip() {
        let test_value = TestStruct { bytes: None };

        assert_tokens(
            &test_value,
            &[
                Token::Struct {
                    name: "TestStruct",
                    len: 1,
                },
                Token::Str("bytes"),
                Token::None,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn some_json_serialization_round_trip() {
        let test_value = TestStruct {
            bytes: Some(BigUint::from(12345)),
        };
        let expected_json = r#"{"bytes":"MDk"}"#;

        let actual_json = serde_json::to_string(&test_value).unwrap();
        assert_eq!(expected_json, actual_json);

        let deserialized_value: TestStruct = serde_json::from_str(&actual_json).unwrap();
        assert_eq!(test_value, deserialized_value);
    }

    #[test]
    fn none_json_serialization_round_trip() {
        let test_value = TestStruct { bytes: None };
        let expected_json = r#"{"bytes":null}"#;

        let actual_json = serde_json::to_string(&test_value).unwrap();
        assert_eq!(expected_json, actual_json);

        let deserialized_value: TestStruct = serde_json::from_str(&actual_json).unwrap();
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
            2661337731, 446995658, 1209332140, 183172752, 955894533,
            3140848734, 581365968, 3217299938, 3520742369, 1559833632,
            1548159735, 2303031139, 1726816051, 92775838, 37272772, 1817499268,
            2876656510, 1328166076, 2779910671, 4258539214, 2834014041,
            3172137349, 4008354576, 121660540, 1941402830, 1620936445,
            993798294, 47616683, 272681116, 983097263, 225284287, 3494334405,
            4005126248, 1126447551, 2189379704, 4098746126, 3730484719,
            3232696701, 2583545877, 428738419, 2533069420, 2922211325,
            2227907999, 4154608099, 679827337, 1165541732, 2407118218,
            3485541440, 799756961, 1854157941, 3062830172, 3270332715,
            1431293619, 3068067851, 2238478449, 2704523019, 2826966453,
            1548381401, 3719104923, 2605577849, 2293389158, 273345423,
            169765991, 3539762026,
        ]);
        assert_eq!(a, c);

        assert_eq!(c.as_base64_be().to_string(), s);
    }
}
