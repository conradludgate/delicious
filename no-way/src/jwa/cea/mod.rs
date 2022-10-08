//! [Cryptographic Algorithms for Content Encryption](https://datatracker.ietf.org/doc/html/rfc7518#section-5)
use std::{
    fmt,
    ops::{Index, IndexMut, Range},
};

use crate::errors::Error;

pub(crate) mod aes_cbc_hmac_sha;
pub(crate) mod aes_gcm;
pub use self::aes_gcm::{AesGcm, A128GCM, A192GCM, A256GCM};
pub use aes_cbc_hmac_sha::{AesCbcHmacSha2, A128CBC_HS256, A192CBC_HS384, A256CBC_HS512};
use arrayvec::ArrayVec;
use serde::{Deserialize, Serialize};

/// [Cryptographic Algorithms for Content Encryption](https://datatracker.ietf.org/doc/html/rfc7518#section-5)
pub trait CEA {
    /// The name specified in the `enc` header.
    const ENC: Algorithm;
    /// Initialization Vector (usually an array type)
    type IV;

    /// Generate a random content encryption key
    fn generate_cek() -> Vec<u8>;
    /// Generate a random initialisation vector key
    fn generate_iv() -> Self::IV;

    /// Encrypts the payload
    fn encrypt(
        cek: &[u8],
        payload: &[u8],
        iv: Self::IV,
        aad: &[u8],
    ) -> Result<EncryptionResult, Error>;

    /// Decrypts the payload in place, returning a slice to the payload
    fn decrypt<'r>(cek: &[u8], res: &'r mut EncryptionResult) -> Result<&'r [u8], Error>;
}

/// A packed representation of N slices. Always pre-allocated, does not support resizing
///
/// # Example
/// ```
/// use no_way::jwa::cea::PackedBuffer;
///
/// let buf = PackedBuffer::from([
///     b"additional authenticated data".as_slice(),
///     b"initialisation vector".as_slice(),
///     b"encrypted payload".as_slice(),
///     b"integrity tag".as_slice(),
/// ]);
/// assert_eq!(&buf[0], b"additional authenticated data");
/// assert_eq!(&buf[1], b"initialisation vector");
/// assert_eq!(&buf[2], b"encrypted payload");
/// assert_eq!(&buf[3], b"integrity tag");
///
/// let (buf, sections) = buf.into_raw();
/// assert_eq!(buf, b"additional authenticated datainitialisation vectorencrypted payloadintegrity tag");
/// assert_eq!(sections, [29, 50, 67, 80])
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PackedBuffer<const N: usize> {
    buf: Vec<u8>,
    sections: [usize; N],
}

impl<const N: usize> fmt::Debug for PackedBuffer<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        self.sections.iter().fold(0, |start, &end| {
            list.entry(&&self.buf[start..end]);
            end
        });
        list.finish()
    }
}

/// Construct a `PackedBuffer` from all the slices
impl<const N: usize> From<[&[u8]; N]> for PackedBuffer<N> {
    fn from(slices: [&[u8]; N]) -> Self {
        let len = slices.iter().map(|s| s.len()).sum();
        let mut buf = Vec::with_capacity(len);
        let mut sections = [0; N];

        let mut n = 0;
        for i in 0..N {
            let m = n + slices[i].len();
            buf.extend_from_slice(slices[i]);
            n = m;
            sections[i] = m;
        }

        Self { buf, sections }
    }
}

impl<const N: usize> PackedBuffer<N> {
    /// Constructs a new `PackedBuffer` using the buffer and sections provided.
    ///
    /// # Panics
    /// This will panic if the `sections` value is not monotonically increasing,
    /// or it exceeds the length of the buffer
    pub fn from_raw(buf: Vec<u8>, sections: [usize; N]) -> Self {
        let mut n = 0;
        for &i in &sections {
            assert!(n <= i, "sections must be a monotonically increasing array");
            n = i;
        }
        assert_eq!(
            sections[N - 1],
            buf.len(),
            "provided buffer does not have the correct space"
        );

        Self { buf, sections }
    }

    pub fn into_raw(self) -> (Vec<u8>, [usize; N]) {
        (self.buf, self.sections)
    }

    /// Constructs a new zeroed `PackedBuffer` where each section can fit the length provided
    pub fn new(mut lengths: [usize; N]) -> Self {
        let mut n = 0;
        for len in lengths.iter_mut() {
            n += *len;
            *len = n;
        }
        let buffer = vec![0; n];
        Self {
            buf: buffer,
            sections: lengths,
        }
    }

    /// Splits the packed buffer into N slices
    pub fn split(&self) -> [&[u8]; N] {
        let Self { buf, sections } = self;
        let mut rest: &[u8] = buf;
        let mut output = [rest; N];
        for i in (1..N).rev() {
            let (r, s) = rest.split_at(sections[i - 1]);
            rest = r;
            output[i] = s;
        }
        output[0] = rest;
        output
    }

    /// Splits the packed buffer into N mutable slices
    pub fn split_mut(&mut self) -> [&mut [u8]; N] {
        let Self { buf, sections } = self;
        let mut output: ArrayVec<&mut [u8], N> = ArrayVec::new();
        let mut rest: &mut [u8] = &mut *buf;
        for i in (1..N).rev() {
            let (r, s) = rest.split_at_mut(sections[i - 1]);
            rest = r;
            output.insert(0, s);
        }
        output.insert(0, rest);
        // safety: we guarantee to insert N elements
        unsafe { output.into_inner_unchecked() }
    }

    fn index(&self, index: usize) -> Range<usize> {
        let end = self.sections[index];
        let start = if let Some(i) = index.checked_sub(1) {
            self.sections[i]
        } else {
            0
        };
        start..end
    }

    fn range(&self, index: Range<usize>) -> Range<usize> {
        let start = if let Some(i) = index.start.checked_sub(1) {
            self.sections[i]
        } else {
            0
        };
        let end = if let Some(i) = index.end.checked_sub(1) {
            self.sections[i]
        } else {
            0
        };
        start..end
    }
}

impl<const N: usize> Index<usize> for PackedBuffer<N> {
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output {
        &self.buf[self.index(index)]
    }
}

impl<const N: usize> IndexMut<usize> for PackedBuffer<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let range = self.index(index);
        &mut self.buf[range]
    }
}

impl<const N: usize> Index<Range<usize>> for PackedBuffer<N> {
    type Output = [u8];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.buf[self.range(index)]
    }
}

impl<const N: usize> IndexMut<Range<usize>> for PackedBuffer<N> {
    fn index_mut(&mut self, index: Range<usize>) -> &mut Self::Output {
        let range = self.range(index);
        &mut self.buf[range]
    }
}

/// The result returned from an encryption operation
///
/// It's packed as [AAD,NONCE,PAYLOAD,TAG] to avoid having
/// multiple allocations.
pub type EncryptionResult = PackedBuffer<4>;

impl EncryptionResult {
    pub(crate) fn take_payload(mut self) -> Vec<u8> {
        self.buf.truncate(self.sections[2]);
        self.buf.drain(..self.sections[1]);
        self.buf
    }
}

/// Algorithms meant for content encryption.
/// See [RFC7518#5](https://tools.ietf.org/html/rfc7518#section-5)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum Algorithm {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm enc
    #[serde(rename = "A128CBC-HS256")]
    A128CBC_HS256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm enc
    #[serde(rename = "A192CBC-HS384")]
    A192CBC_HS384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm enc
    #[serde(rename = "A256CBC-HS512")]
    A256CBC_HS512,
    /// AES GCM using 128-bit key
    A128GCM,
    /// AES GCM using 192-bit key
    A192GCM,
    /// AES GCM using 256-bit key
    A256GCM,
}

impl Algorithm {
    /// Turn this content-encryption algorithm into it's
    /// well-known `enc` header name
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A128CBC_HS256 => "A128CBC-HS256",
            Self::A192CBC_HS384 => "A192CBC-HS384",
            Self::A256CBC_HS512 => "A256CBC-HS512",
            Self::A128GCM => "A128GCM",
            Self::A192GCM => "A192GCM",
            Self::A256GCM => "A256GCM",
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::A128GCM
    }
}
