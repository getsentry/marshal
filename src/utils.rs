//! Various utilities, like serialization and deserialization helpers.

pub mod annotated {
    use common::{Map, Values};
    use meta::{should_serialize_meta, Annotated};

    fn skip_if<T, F>(annotated: &Annotated<T>, predicate: F) -> bool
    where
        F: FnOnce(&T) -> bool,
    {
        // Always serialize meta data. The MetaTreeSerializer will automatically remove empty nodes.
        !should_serialize_meta() && annotated.value().map_or(false, predicate)
    }

    pub fn is_none<T>(annotated: &Annotated<Option<T>>) -> bool {
        skip_if(annotated, Option::is_none)
    }

    pub fn is_empty_values<T>(annotated: &Annotated<Values<T>>) -> bool {
        skip_if(annotated, Values::is_empty)
    }

    pub fn is_empty_map<V>(annotated: &Annotated<Map<V>>) -> bool {
        skip_if(annotated, Map::is_empty)
    }
}

/// Serde buffers.
pub mod buffer {
    pub use serde::private::de::{
        Content, ContentDeserializer, ContentRefDeserializer, ContentRepr,
    };
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

    pub struct ForwardSerialize<'a, T: 'a, C>(pub &'a T, pub C);

    impl<'a, T: 'a, C> Serialize for ForwardSerialize<'a, T, C>
    where
        C: CustomSerialize<T>,
    {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            C::serialize(self.0, serializer)
        }
    }
}

/// Serde module for `chrono::DateTime`.
pub mod serde_chrono {
    use std::fmt;

    use chrono::{DateTime, TimeZone, Utc};
    use serde::{de, ser};

    use meta::Annotated;
    use utils::serde::{CustomDeserialize, CustomSerialize, ForwardSerialize};

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

    struct De(DateTime<Utc>);

    impl<'de> de::Deserialize<'de> for De {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            Ok(De(deserializer
                .deserialize_any(SecondsTimestampVisitor)?
                .with_timezone(&Utc)))
        }
    }

    pub struct SerdeDateTime;

    impl<'de> CustomDeserialize<'de, DateTime<Utc>> for SerdeDateTime {
        fn deserialize<D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            use serde::Deserialize;
            Ok(De::deserialize(deserializer)?.0)
        }
    }

    impl<'de> CustomDeserialize<'de, Option<DateTime<Utc>>> for SerdeDateTime {
        fn deserialize<D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            use serde::Deserialize;
            Ok(Option::<De>::deserialize(deserializer)?.map(|de| de.0))
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

    impl CustomSerialize<Option<DateTime<Utc>>> for SerdeDateTime {
        fn serialize<S>(datetime: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: ser::Serializer,
        {
            match datetime {
                Some(d) => serializer.serialize_some(&ForwardSerialize(d, SerdeDateTime)),
                None => serializer.serialize_none(),
            }
        }
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Annotated<T>, D::Error>
    where
        D: de::Deserializer<'de>,
        SerdeDateTime: CustomDeserialize<'de, T>,
    {
        Annotated::deserialize_with(deserializer, SerdeDateTime)
    }

    pub fn serialize<T, S>(value: &Annotated<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
        SerdeDateTime: CustomSerialize<T>,
    {
        value.serialize_with(serializer, SerdeDateTime)
    }
}
