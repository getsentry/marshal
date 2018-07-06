//! Various utilities, like serialization and deserialization helpers.

pub mod annotated {
    use common::Values;
    use meta::Annotated;

    pub fn is_none<T>(annotated: &Annotated<Option<T>>) -> bool {
        // TODO: Consider meta serialization
        annotated.value().map_or(true, Option::is_none)
    }

    pub fn is_empty_values<T>(annotated: &Annotated<Values<T>>) -> bool {
        // TODO: Consider meta serialization
        annotated.value().map_or(true, Values::is_empty)
    }
}

/// Defines the `CustomDeserialize` trait.
pub mod serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::marker::PhantomData;

    /// Provides a custom `serde::Deserialize` implementation for a type.
    pub trait CustomDeserialize<'de, T> {
        /// Deserialize the value from the given Serde deserializer.
        fn deserialize<D>(deserializer: D) -> Result<T, D::Error>
        where
            D: Deserializer<'de>;
    }

    /// Implementation of `CustomDeserialize` that uses the type's `Deserialize` implementation.
    #[derive(Debug)]
    pub struct DefaultDeserialize<T>(PhantomData<T>);

    impl<T> Default for DefaultDeserialize<T> {
        fn default() -> Self {
            DefaultDeserialize(PhantomData)
        }
    }

    impl<'de, T: Deserialize<'de>> CustomDeserialize<'de, T> for DefaultDeserialize<T> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<T, D::Error> {
            T::deserialize(deserializer)
        }
    }

    /// Provides a custom `serde::Serialize` implementation for a type.
    pub trait CustomSerialize<T> {
        /// Serialize this value into the given Serde serializer.
        fn serialize<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer;
    }

    /// Implementation of `CustomSerialize` that uses the type's `Serialize` implementation.
    #[derive(Debug)]
    pub struct DefaultSerialize<T>(PhantomData<T>);

    impl<T> Default for DefaultSerialize<T> {
        fn default() -> Self {
            DefaultSerialize(PhantomData)
        }
    }

    impl<T: Serialize> CustomSerialize<T> for DefaultSerialize<T> {
        fn serialize<S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
            value.serialize(serializer)
        }
    }
}

/// Serde module for `chrono::DateTime`.
pub mod serde_chrono {
    use std::fmt;

    use chrono::{DateTime, TimeZone, Utc};
    use serde::{de, ser};

    use meta::Annotated;
    use utils::serde::{CustomDeserialize, CustomSerialize};

    pub fn timestamp_to_datetime(ts: f64) -> DateTime<Utc> {
        let secs = ts as i64;
        let micros = (ts.fract() * 1_000_000f64) as u32;
        Utc.timestamp_opt(secs, micros * 1000).unwrap()
    }

    struct SecondsTimestampVisitor;

    impl<'de> de::Visitor<'de> for SecondsTimestampVisitor {
        type Value = DateTime<Utc>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "a unix timestamp")
        }

        fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
            Ok(timestamp_to_datetime(value))
        }

        fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
            Ok(Utc.timestamp_opt(value, 0).unwrap())
        }

        fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
            Ok(Utc.timestamp_opt(value as i64, 0).unwrap())
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
            value.parse().map_err(|e| E::custom(format!("{}", e)))
        }
    }

    struct SerdeDateTime;

    impl<'de> CustomDeserialize<'de, DateTime<Utc>> for SerdeDateTime {
        fn deserialize<D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            Ok(deserializer
                .deserialize_any(SecondsTimestampVisitor)?
                .with_timezone(&Utc))
        }
    }

    impl CustomSerialize<DateTime<Utc>> for SerdeDateTime {
        fn serialize<S>(datetime: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: ser::Serializer,
        {
            if datetime.timestamp_subsec_nanos() == 0 {
                serializer.serialize_i64(datetime.timestamp())
            } else {
                let micros = datetime.timestamp_subsec_micros() as f64 / 1_000_000f64;
                serializer.serialize_f64(datetime.timestamp() as f64 + micros)
            }
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Annotated<DateTime<Utc>>, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Annotated::deserialize_with(deserializer, SerdeDateTime)
    }

    pub fn serialize<S>(value: &Annotated<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        value.serialize_with(serializer, SerdeDateTime)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::Deserializer;

        #[test]
        fn test_timestamp() {
            let deserializer = &mut Deserializer::from_str("946684800");
            assert_eq!(
                deserialize(deserializer).unwrap(),
                Annotated::from(Utc.ymd(2000, 1, 1).and_hms(0, 0, 0))
            );
        }

        #[test]
        fn test_date() {
            let deserializer = &mut Deserializer::from_str("\"2000-01-01T00:00:00Z\"");
            assert_eq!(
                deserialize(deserializer).unwrap(),
                Annotated::from(Utc.ymd(2000, 1, 1).and_hms(0, 0, 0))
            );
        }

        #[test]
        fn test_invalid_date() {
            let deserializer = &mut Deserializer::from_str("\"invalid\"");
            assert_eq!(
                deserialize(deserializer).unwrap(),
                Annotated::from_error("input contains invalid characters")
            );
        }

        #[test]
        fn test_invalid_type() {
            let deserializer = &mut Deserializer::from_str("true");
            assert_eq!(
                deserialize(deserializer).unwrap(),
                Annotated::from_error("invalid type: boolean `true`, expected a unix timestamp")
            );
        }
    }
}
