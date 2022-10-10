use core::str::FromStr;
use std::num::NonZeroU32;

use super::BigUint;

impl FromStr for BigUint {
    type Err = ParseBigIntError;

    #[inline]
    fn from_str(s: &str) -> Result<BigUint, ParseBigIntError> {
        BigUint::from_str_radix(s, NonZeroU32::new(10).unwrap())
    }
}

// Convert from a power of two radix (bits == ilog2(radix)) where bits evenly divides
// u32::BITS
pub(super) fn from_bitwise_digits_le(v: &[u8], bits: u8) -> BigUint {
    debug_assert!(!v.is_empty() && bits <= 8 && 32 % bits == 0);
    debug_assert!(v.iter().all(|&c| u32::from(c) < (1 << bits)));

    let digits_per_big_digit = 32 / bits;

    let data = v
        .chunks(digits_per_big_digit.into())
        .map(|chunk| {
            chunk
                .iter()
                .rev()
                .fold(0, |acc, &c| (acc << bits) | u32::from(c))
        })
        .collect();

    BigUint::from_chunks(data)
}

fn div_ceil(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

// Convert from a power of two radix (bits == ilog2(radix)) where bits doesn't evenly divide
// u32::BITS
fn from_inexact_bitwise_digits_le(v: &[u8], bits: u8) -> BigUint {
    debug_assert!(!v.is_empty() && bits <= 8 && 32 % bits != 0);
    debug_assert!(v.iter().all(|&c| u32::from(c) < (1 << bits)));

    let total_bits = (v.len() as usize).saturating_mul(bits.into());
    let big_digits = div_ceil(total_bits, 32);
    let mut data = Vec::with_capacity(big_digits);

    let mut d = 0;
    let mut dbits = 0; // number of bits we currently have in d

    // walk v accumululating bits in d; whenever we accumulate 32 in d, spit out a
    // big_digit:
    for &c in v {
        d |= u32::from(c) << dbits;
        dbits += bits;

        if dbits >= 32 {
            data.push(d);
            dbits -= 32;
            // if dbits was > 32, we dropped some of the bits in c (they couldn't fit
            // in d) - grab the bits we lost here:
            d = u32::from(c) >> (bits - dbits);
        }
    }

    if dbits > 0 {
        debug_assert!(dbits < 32);
        data.push(d as u32);
    }

    BigUint::from_chunks(data)
}

// Read little-endian radix digits
fn from_radix_digits_be(v: &[u8], radix: NonZeroU32) -> BigUint {
    debug_assert!(!v.is_empty() && !radix.is_power_of_two());
    debug_assert!(v.iter().all(|&c| u32::from(c) < radix.get()));

    #[cfg(feature = "std")]
    let radix_log2 = f64::from(radix).log2();
    #[cfg(not(feature = "std"))]
    let radix_log2 = ilog2(radix.next_power_of_two()) as f64;

    // Estimate how big the result will be, so we can pre-allocate it.
    let bits = radix_log2 * v.len() as f64;
    let big_digits = (bits / 32 as f64).ceil();
    let mut data = Vec::with_capacity(big_digits.to_usize().unwrap_or(0));

    let (base, power) = get_radix_base(radix);
    let radix = radix as u32;

    let r = v.len() % power;
    let i = if r == 0 { power } else { r };
    let (head, tail) = v.split_at(i);

    let first = head.iter().fold(0, |acc, &d| acc * radix + u32::from(d));
    data.push(first);

    debug_assert!(tail.len() % power == 0);
    for chunk in tail.chunks(power) {
        if data.last() != Some(&0) {
            data.push(0);
        }

        let mut carry = 0;
        for d in data.iter_mut() {
            *d = mac_with_carry(0, *d, base, &mut carry);
        }
        debug_assert!(carry == 0);

        let n = chunk.iter().fold(0, |acc, &d| acc * radix + u32::from(d));
        add2(&mut data, &[n]);
    }

    BigUint::from_chunks(data)
}

pub(super) fn from_radix_be(buf: &[u8], radix: NonZeroU32) -> Option<BigUint> {
    assert!(
        2 <= radix && radix <= 256,
        "The radix must be within 2...256"
    );

    if buf.is_empty() {
        return Some(Zero::zero());
    }

    if radix != 256 && buf.iter().any(|&b| b >= radix as u8) {
        return None;
    }

    let res = if radix.is_power_of_two() {
        // Powers of two can use bitwise masks and shifting instead of multiplication
        let bits = ilog2(radix);
        let mut v = Vec::from(buf);
        v.reverse();
        if 32 % bits == 0 {
            from_bitwise_digits_le(&v, bits)
        } else {
            from_inexact_bitwise_digits_le(&v, bits)
        }
    } else {
        from_radix_digits_be(buf, radix)
    };

    Some(res)
}

pub(super) fn from_radix_le(buf: &[u8], radix: NonZeroU32) -> Option<BigUint> {
    assert!(
        2 <= radix && radix <= 256,
        "The radix must be within 2...256"
    );

    if buf.is_empty() {
        return Some(Zero::zero());
    }

    if radix != 256 && buf.iter().any(|&b| b >= radix as u8) {
        return None;
    }

    let res = if radix.is_power_of_two() {
        // Powers of two can use bitwise masks and shifting instead of multiplication
        let bits = ilog2(radix);
        if 32 % bits == 0 {
            from_bitwise_digits_le(buf, bits)
        } else {
            from_inexact_bitwise_digits_le(buf, bits)
        }
    } else {
        let mut v = Vec::from(buf);
        v.reverse();
        from_radix_digits_be(&v, radix)
    };

    Some(res)
}

pub enum ParseBigIntError {
    Invalid,
    Empty,
}

impl BigUint {
    /// Creates and initializes a `BigUint`.
    pub fn from_str_radix(s: &str, radix: NonZeroU32) -> Result<BigUint, ParseBigIntError> {
        assert!(2 <= radix && radix <= 36, "The radix must be within 2...36");
        let mut s = s;
        if s.starts_with('+') {
            let tail = &s[1..];
            if !tail.starts_with('+') {
                s = tail
            }
        }

        if s.is_empty() {
            return Err(ParseBigIntError::Empty);
        }

        if s.starts_with('_') {
            // Must lead with a real digit!
            return Err(ParseBigIntError::Invalid);
        }

        // First normalize all characters to plain digit values
        let mut v = Vec::with_capacity(s.len());
        for b in s.bytes() {
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'z' => b - b'a' + 10,
                b'A'..=b'Z' => b - b'A' + 10,
                b'_' => continue,
                _ => core::u8::MAX,
            };
            if d < radix as u8 {
                v.push(d);
            } else {
                return Err(ParseBigIntError::Invalid);
            }
        }

        let res = if radix.is_power_of_two() {
            // Powers of two can use bitwise masks and shifting instead of multiplication
            let bits = ilog2(radix);
            v.reverse();
            if 32 % bits == 0 {
                from_bitwise_digits_le(&v, bits)
            } else {
                from_inexact_bitwise_digits_le(&v, bits)
            }
        } else {
            from_radix_digits_be(&v, radix)
        };
        Ok(res)
    }
}

fn high_bits_to_u64(v: &BigUint) -> u64 {
    match v.data.len() {
        0 => 0,
        1 => {
            // XXX Conversion is useless if already 64-bit.
            #[allow(clippy::useless_conversion)]
            let v0 = u64::from(v.data[0]);
            v0
        }
        _ => {
            let mut bits = v.bits();
            let mut ret = 0u64;
            let mut ret_bits = 0;

            for d in v.data.iter().rev() {
                let digit_bits = (bits - 1) % u64::from(32) + 1;
                let bits_want = Ord::min(64 - ret_bits, digit_bits);

                if bits_want != 64 {
                    ret <<= bits_want;
                }
                // XXX Conversion is useless if already 64-bit.
                #[allow(clippy::useless_conversion)]
                let d0 = u64::from(*d) >> (digit_bits - bits_want);
                ret |= d0;
                ret_bits += bits_want;
                bits -= bits_want;

                if ret_bits == 64 {
                    break;
                }
            }

            ret
        }
    }
}

// Extract bitwise digits that evenly divide u32
pub(super) fn to_bitwise_digits_le(u: &BigUint, bits: u8) -> Vec<u8> {
    debug_assert!(!u.is_zero() && bits <= 8 && 32 % bits == 0);

    let last_i = u.data.len() - 1;
    let mask: u32 = (1 << bits) - 1;
    let digits_per_big_digit = 32 / bits;
    let digits = div_ceil(u.bits(), bits as usize);
    let mut res = Vec::with_capacity(digits);

    for mut r in u.data[..last_i].iter().cloned() {
        for _ in 0..digits_per_big_digit {
            res.push((r & mask) as u8);
            r >>= bits;
        }
    }

    let mut r = u.data[last_i];
    while r != 0 {
        res.push((r & mask) as u8);
        r >>= bits;
    }

    res
}

// Extract bitwise digits that don't evenly divide u32
fn to_inexact_bitwise_digits_le(u: &BigUint, bits: u8) -> Vec<u8> {
    debug_assert!(!u.is_zero() && bits <= 8 && 32 % bits != 0);

    let mask: u32 = (1 << bits) - 1;
    let digits = div_ceil(u.bits(), bits as usize);
    let mut res = Vec::with_capacity(digits);

    let mut r = 0;
    let mut rbits = 0;

    for c in &u.data {
        r |= *c << rbits;
        rbits += 32;

        while rbits >= bits {
            res.push((r & mask) as u8);
            r >>= bits;

            // r had more bits than it could fit - grab the bits we lost
            if rbits > 32 {
                r = *c >> (32 - (rbits - bits));
            }

            rbits -= bits;
        }
    }

    if rbits != 0 {
        res.push(r as u8);
    }

    while let Some(&0) = res.last() {
        res.pop();
    }

    res
}

// Extract little-endian radix digits
#[inline(always)] // forced inline to get const-prop for radix=10
pub(super) fn to_radix_digits_le(u: &BigUint, radix: NonZeroU32) -> Vec<u8> {
    debug_assert!(!u.is_zero() && !radix.is_power_of_two());

    #[cfg(feature = "std")]
    let radix_log2 = f64::from(radix).log2();
    #[cfg(not(feature = "std"))]
    let radix_log2 = ilog2(radix) as f64;

    // Estimate how big the result will be, so we can pre-allocate it.
    let radix_digits = ((u.bits() as f64) / radix_log2).ceil();
    let mut res = Vec::with_capacity(radix_digits.to_usize().unwrap_or(0));

    let mut digits = u.clone();

    let (base, power) = get_radix_base_half(radix);
    let radix = radix as u32;

    // For very large numbers, the O(n²) loop of repeated `div_rem_digit` dominates the
    // performance. We can mitigate this by dividing into chunks of a larger base first.
    // The threshold for this was chosen by anecdotal performance measurements to
    // approximate where this starts to make a noticeable difference.
    if digits.data.len() >= 64 {
        let mut big_base = BigUint::from(base * base);
        let mut big_power = 2usize;

        // Choose a target base length near √n.
        let target_len = digits.data.len().sqrt();
        while big_base.data.len() < target_len {
            big_base = &big_base * &big_base;
            big_power *= 2;
        }

        // This outer loop will run approximately √n times.
        while digits > big_base {
            // This is still the dominating factor, with n digits divided by √n digits.
            let (q, mut big_r) = digits.div_rem(&big_base);
            digits = q;

            // This inner loop now has O(√n²)=O(n) behavior altogether.
            for _ in 0..big_power {
                let (q, mut r) = div_rem_digit(big_r, base);
                big_r = q;
                for _ in 0..power {
                    res.push((r % radix) as u8);
                    r /= radix;
                }
            }
        }
    }

    while digits.data.len() > 1 {
        let (q, mut r) = div_rem_digit(digits, base);
        for _ in 0..power {
            res.push((r % radix) as u8);
            r /= radix;
        }
        digits = q;
    }

    let mut r = digits.data[0];
    while r != 0 {
        res.push((r % radix) as u8);
        r /= radix;
    }

    res
}

fn ilog2(radix: NonZeroU32) -> u32 {
    31 - radix.leading_zeros()
}

pub(super) fn to_radix_le(u: &BigUint, radix: NonZeroU32) -> Vec<u8> {
    if u.is_zero() {
        vec![0]
    } else if radix.is_power_of_two() {
        // Powers of two can use bitwise masks and shifting instead of division
        let bits = ilog2(radix);
        if 32 % bits == 0 {
            to_bitwise_digits_le(u, bits)
        } else {
            to_inexact_bitwise_digits_le(u, bits)
        }
    } else if radix == 10 {
        // 10 is so common that it's worth separating out for const-propagation.
        // Optimizers can often turn constant division into a faster multiplication.
        to_radix_digits_le(u, 10)
    } else {
        to_radix_digits_le(u, radix)
    }
}

pub(crate) fn to_str_radix_reversed(u: &BigUint, radix: NonZeroU32) -> Vec<u8> {
    assert!(2 <= radix && radix <= 36, "The radix must be within 2...36");

    if u.is_zero() {
        return vec![b'0'];
    }

    let mut res = to_radix_le(u, radix);

    // Now convert everything to ASCII digits.
    for r in &mut res {
        debug_assert!(u32::from(*r) < radix);
        if *r < 10 {
            *r += b'0';
        } else {
            *r += b'a' - 10;
        }
    }
    res
}

/// Returns the greatest power of the radix for 16 bits
#[inline]
fn get_radix_base_half(radix: NonZeroU32) -> (u32, usize) {
    const BASES: [(u32, usize); 256] = {
        let mut output = [(0, 0); 256];

        let mut radix = 1u32;
        while radix < 257 {
            output[radix as usize - 1] = if radix.is_power_of_two() {
                (0, 0)
            } else {
                let mut power = 1;
                let mut base = radix;

                while let Some(b) = base.checked_mul(radix) {
                    if b > 0xffff {
                        break;
                    }
                    base = b;
                    power += 1;
                }
                (base, power)
            };
            radix += 1;
        }
    };

    debug_assert!(
        2 <= radix && radix <= 256,
        "The radix must be within 2...256"
    );
    debug_assert!(!radix.is_power_of_two());

    BASES[radix - 1 as usize]
}

/// Returns the greatest power of the radix for 32 bits
#[inline]
fn get_radix_base(radix: NonZeroU32) -> (u32, usize) {
    const BASES: [(u32, usize); 256] = {
        let mut output = [(0, 0); 256];

        let mut radix = 1u32;
        while radix < 257 {
            output[radix as usize - 1] = if radix.is_power_of_two() {
                (0, 0)
            } else {
                let mut power = 1;
                let mut base = radix;

                while let Some(b) = base.checked_mul(radix) {
                    base = b;
                    power += 1;
                }
                (base, power)
            };
            radix += 1;
        }
    };

    debug_assert!(
        2 <= radix && radix <= 256,
        "The radix must be within 2...256"
    );
    debug_assert!(!radix.is_power_of_two());

    BASES[radix - 1 as usize]
}
