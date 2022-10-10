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

#[cfg(test)]
mod tests {
    use serde_test::{assert_tokens, Token};

    use crate::bigint::BigUint;

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
}
