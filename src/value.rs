//! Implements an arbitrary type object for the protocol.

use std::collections::BTreeMap;
use std::fmt;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use meta::Annotated;

/// A list of annotated values.
pub type Array<V> = Vec<Annotated<V>>;

/// A map of annotated values.
pub type Map<V> = BTreeMap<String, Annotated<V>>;

/// Holds an arbitrary type supported by the protocol.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// A null value (None, unit).
    Null,
    /// A boolean vlaue.
    Bool(bool),
    /// An unsigned int 32.
    U32(u32),
    /// A signed int 32.
    I32(i32),
    /// An unsigned int 64.
    U64(u64),
    /// A signed int 64.
    I64(i64),
    /// A 32bit float.
    F32(f32),
    /// A 64bit float.
    F64(f64),
    /// A string.
    String(String),
    /// An array of annotated values.
    Array(Array<Value>),
    /// A map of annotated values.
    Map(Map<Value>),
}

macro_rules! declare_from {
    ($ty:ident, $value_ty:ident) => {
        impl From<$ty> for Value {
            fn from(value: $ty) -> Value {
                Value::$value_ty(value)
            }
        }
    };
}

declare_from!(bool, Bool);
declare_from!(u32, U32);
declare_from!(i32, I32);
declare_from!(u64, U64);
declare_from!(i64, I64);
declare_from!(f32, F32);
declare_from!(f64, F64);
declare_from!(String, String);

struct ValueVisitor;

impl<'de> de::Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a valid value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Bool(v))
    }

    fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::I32(v.into()))
    }

    fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::I32(v.into()))
    }

    fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::I32(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::I64(v))
    }

    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::U32(v.into()))
    }

    fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::U32(v.into()))
    }

    fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::U32(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::U64(v))
    }

    fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::F32(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::F64(v))
    }

    fn visit_char<E>(self, v: char) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(v.to_string()))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(v.to_string()))
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(v.to_string()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(v))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(String::from_utf8_lossy(v).into_owned()))
    }

    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(String::from_utf8_lossy(v).into_owned()))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(String::from_utf8_lossy(&v).into_owned()))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Value::deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Value::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut vec = Vec::new();
        while let Some(el) = seq.next_element()? {
            vec.push(el);
        }
        Ok(Value::Array(vec))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut m = Map::new();
        while let Some((key, value)) = map.next_entry()? {
            m.insert(key, value);
        }
        Ok(Value::Map(m))
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: de::EnumAccess<'de>,
    {
        let (v, _) = data.variant()?;
        Ok(v)
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match *self {
            Value::Null => serializer.serialize_none(),
            Value::Bool(b) => serializer.serialize_bool(b),
            Value::U32(u) => serializer.serialize_u32(u),
            Value::I32(i) => serializer.serialize_i32(i),
            Value::U64(u) => serializer.serialize_u64(u),
            Value::I64(i) => serializer.serialize_i64(i),
            Value::F32(f) => serializer.serialize_f32(f),
            Value::F64(f) => serializer.serialize_f64(f),
            Value::String(ref s) => serializer.serialize_str(s),
            Value::Array(ref a) => {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(a.len()))?;
                for value in a {
                    seq.serialize_element(value)?;
                }
                seq.end()
            }
            Value::Map(ref m) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(m.len()))?;
                for (ref key, ref val) in m {
                    map.serialize_entry(key, val)?;
                }
                map.end()
            }
        }
    }
}
