
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
