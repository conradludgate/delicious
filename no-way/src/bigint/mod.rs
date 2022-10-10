mod add;
mod base64;
mod serde;

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
    pub const fn zero() -> Self {
        Self { data: Vec::new() }
    }
    /// Create a new bigint with little endian u32 chunks
    pub fn new(data: Vec<u32>) -> Self {
        Self { data }
    }

    /// Converts big endian u32s into a `BigUInt`.
    /// # Safety
    /// `full_bytes` must be in bounds of `data`
    #[inline(never)]
    unsafe fn from_be_bytes_u32(mut data: Vec<u32>, full_bytes: usize) -> Self {
        #[cfg(target_endian = "little")]
        {
            // the chunks and the u32 bytes need reversing.
            // reversing all bytes has that effect
            bytemuck::cast_slice_mut::<u32, u8>(&mut data)
                .get_unchecked_mut(..full_bytes)
                .reverse();
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
        // Safety:
        // data in bytes is larger than b.len()
        unsafe {
            bytemuck::cast_slice_mut(&mut data)
                .get_unchecked_mut(..b.len())
                .copy_from_slice(b);

            Self::from_be_bytes_u32(data, b.len())
        }
    }

    /// Extract the big endian bytes from this `BigUint`
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
}
