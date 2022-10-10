use std::ops::{Add, AddAssign};

use super::BigUint;

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

#[cfg(test)]
mod tests {
    use crate::bigint::BigUint;

    fn add(a: Vec<u32>, b: Vec<u32>) -> BigUint {
        let a = BigUint::from_chunks(a);
        let b = BigUint::from_chunks(b);
        let c = a.clone() + &b;
        let d = b + &a;
        assert_eq!(c, d);
        c
    }

    #[test]
    fn add_same_size() {
        let c = add(vec![u32::MAX], vec![2]);
        assert_eq!(c, BigUint::from_chunks(vec![1, 1]));
    }

    #[test]
    fn add_multiple_carry() {
        let c = add(vec![u32::MAX, u32::MAX, 1, u32::MAX], vec![2]);
        assert_eq!(c, BigUint::from_chunks(vec![1, 0, 2, u32::MAX]));
    }
}
