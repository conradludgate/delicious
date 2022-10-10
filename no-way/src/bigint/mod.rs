mod add;
mod base64;
mod serde;
// mod radix;

pub use base64::BigUintBase64Be;

/// A 'big unsigned integer' type.
///
/// Offers arbitrary size integers, and very fast decoding/encoding from base64
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BigUint {
    /// data stored as little endian u32 (the least significant u32 chunks are at the start of the array).
    /// The bytes within the u32 are stored native endian.
    ///
    /// Eg u32::MAX + 1 would be stored as vec![0, 1]
    data: Vec<u32>,
}

impl BigUint {
    /// Equivalent to `BigUint::from(0)`
    pub const fn zero() -> Self {
        Self { data: Vec::new() }
    }

    /// Create a new bigint with little endian u32 chunks
    pub fn from_chunks(mut data: Vec<u32>) -> Self {
        while data.last() == Some(&0) {
            data.pop();
        }
        Self { data }
    }

    /// Extracts the chunks used by this big int
    pub fn into_chunks(self) -> Vec<u32> {
        self.data
    }

    /// Converts big endian u32s into a `BigUInt`.
    /// # Safety
    /// `full_bytes` must be in bounds of `data`
    unsafe fn from_be_bytes_u32(mut data: Vec<u32>, full_bytes: usize) -> Self {
        data.truncate((full_bytes + 3) / 4); // round up bytes to get number of chunks
        #[cfg(target_endian = "little")]
        {
            // the chunks and the u32 bytes need reversing.
            // reversing all bytes has that effect
            bytemuck::cast_slice_mut::<u32, u8>(&mut data)
                .get_unchecked_mut(..full_bytes)
                .reverse();
        }
        #[cfg(not(target_endian = "little"))]
        {
            // only the chunks need reversing into little endian.
            // u32 bytes are big-endian natively so they can remain
            data.reverse();
        }

        Self { data }
    }

    /// Converts little endian u32s into a `BigUInt`.
    fn from_le_bytes_u32(mut data: Vec<u32>) -> Self {
        // make sure each chunk is in native endian
        for chunk in &mut data {
            *chunk = u32::from_le(*chunk);
        }

        // all the chunks are in the correct order already however

        Self { data }
    }

    /// Create a new `BigUint` from big endian bytes
    ///
    /// ```
    /// use no_way::bigint::BigUint;
    /// assert_eq!(
    ///     BigUint::from_be_bytes(&[1, 2, 3, 4, 5, 6]),
    ///     BigUint::from_chunks(vec![0x03040506, 0x0102])
    /// )
    /// ```
    pub fn from_be_bytes(b: &[u8]) -> Self {
        let mut data = vec![0u32; (b.len() + 3) / 4];
        // Safety:
        // data in bytes is larger than b.len()
        unsafe {
            bytemuck::cast_slice_mut(&mut data)
                .get_unchecked_mut(..b.len())
                .copy_from_slice(b);

            Self::from_be_bytes_u32(data, b.len())
        }
    }

    /// Create a new `BigUint` from little endian bytes
    ///
    /// ```
    /// use no_way::bigint::BigUint;
    /// assert_eq!(
    ///     BigUint::from_le_bytes(&[1, 2, 3, 4, 5, 6]),
    ///     BigUint::from_chunks(vec![0x04030201, 0x0605])
    /// )
    /// ```
    pub fn from_le_bytes(b: &[u8]) -> Self {
        let mut data = vec![0u32; (b.len() + 3) / 4];

        // Safety:
        // data in bytes is larger than b.len()
        unsafe {
            bytemuck::cast_slice_mut(&mut data)
                .get_unchecked_mut(..b.len())
                .copy_from_slice(b);
        }

        Self::from_le_bytes_u32(data)
    }

    /// Extract the big endian bytes from this `BigUint`
    ///
    /// ```
    /// use no_way::bigint::BigUint;
    /// assert_eq!(
    ///     BigUint::from_chunks(vec![0x03040506, 0x0102]).to_be_bytes(),
    ///     &[1, 2, 3, 4, 5, 6],
    /// )
    /// ```
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.data.len() * 4);
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

    /// Extract the big endian bytes from this `BigUint`
    ///
    /// ```
    /// use no_way::bigint::BigUint;
    /// assert_eq!(
    ///     BigUint::from_chunks(vec![0x04030201, 0x0605]).to_le_bytes(),
    ///     &[1, 2, 3, 4, 5, 6],
    /// )
    /// ```
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut output = bytemuck::cast_slice::<u32, u8>(&self.data).to_vec();
        for chunk in &mut output {
            *chunk = chunk.to_le();
        }
        while output.last() == Some(&0) {
            output.pop();
        }
        output
    }

    pub fn bits(&self) -> usize {
        let sub = match self.data.last() {
            Some(l) => l.leading_zeros() as usize,
            None => return 0,
        };
        self.data.len() * 32 - sub
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
