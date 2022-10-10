use base64ct::Encoding;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::Serialize;

use std::fmt::Debug;

/// Tests that `value` can be serialized to JSON, and then back to type `T` and that the deserialized type `T`
/// is equal to the provided `value`.
/// If `expected_json` is provided, it will be deserialized to `T` and checked for equality with `value`.
pub fn assert_serde_json<T>(value: &T, expected_json: Option<&str>)
where
    T: Serialize + DeserializeOwned + Debug + PartialEq,
{
    let serialized = dbg!(serde_json::to_string_pretty(value).unwrap());
    let deserialized: T = serde_json::from_str(&serialized).unwrap();
    assert_eq!(value, &deserialized);

    if let Some(expected_json) = expected_json {
        let deserialized: T = serde_json::from_str(expected_json).unwrap();
        assert_eq!(value, &deserialized);
    }
}

pub fn random_vec(len: usize) -> Vec<u8> {
    let mut nonce = vec![0; len];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut nonce = [0; N];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

pub fn fromb64(s: &str) -> Vec<u8> {
    crate::B64::decode_vec(s).unwrap()
}
