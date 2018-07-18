//! Common data structures.

use std::collections::BTreeMap;
use std::fmt;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use super::meta::Annotated;

/// A list of annotated values.
pub type Array<V> = Vec<Annotated<V>>;

/// A map of annotated values.
pub type Map<V> = BTreeMap<String, Annotated<V>>;

/// Holds an arbitrary type supported by the protocol.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// A null value (None, unit).
    Null,
    /// A boolean value.
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

impl<'a> From<&'a str> for Value {
    fn from(string: &'a str) -> Value {
        Value::String(string.to_string())
    }
}

struct ValueVisitor;

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Value::Null => write!(f, "null"),
            Value::Bool(val) => write!(f, "{}", val),
            Value::U32(val) => write!(f, "{}", val),
            Value::I32(val) => write!(f, "{}", val),
            Value::U64(val) => write!(f, "{}", val),
            Value::I64(val) => write!(f, "{}", val),
            Value::F32(val) => write!(f, "{}", val),
            Value::F64(val) => write!(f, "{}", val),
            Value::String(ref val) => write!(f, "{}", val),
            Value::Array(ref val) => {
                write!(f, "[")?;
                for (idx, item) in val.iter().enumerate() {
                    if idx > 0 {
                        write!(f, ", ")?;
                    }
                    if let Some(ref value) = item.value() {
                        write!(f, "{}", value)?;
                    } else {
                        write!(f, "null")?;
                    }
                }
                write!(f, "]")
            }
            Value::Map(ref val) => {
                write!(f, "{{")?;
                for (idx, (key, value)) in val.iter().enumerate() {
                    if idx > 0 {
                        write!(f, ", ")?;
                    }
                    if let Some(ref value) = value.value() {
                        write!(f, "{}: {}", key, value)?;
                    } else {
                        write!(f, "{}: null", key)?;
                    }
                }
                write!(f, "}}")
            }
        }
    }
}

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

/// A wrapper type for collections with attached meta data.
///
/// The JSON payload can either directly be an array or an object containing a `values` field and
/// arbitrary other fields. All other fields will be collected into `Values::data` when
/// deserializing and re-serialized in the same place. The shorthand array notation is always
/// reserialized as object.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Values<T> {
    /// The values of the collection.
    pub values: Annotated<Array<T>>,
    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten, default)]
    pub other: Annotated<Map<Value>>,
}

impl<T> Values<T> {
    /// Creates an empty values struct.
    pub fn new() -> Values<T> {
        Values {
            values: Array::new().into(),
            other: Map::new().into(),
        }
    }

    /// Checks whether this struct is empty in both values and data.
    pub fn is_empty(&self) -> bool {
        self.values.value().map_or(false, Array::is_empty)
            && self.other.value().map_or(false, Map::is_empty)
    }
}

impl<T> Default for Values<T> {
    fn default() -> Values<T> {
        // Default implemented manually even if <T> does not impl Default.
        Values::new()
    }
}

impl<T> From<Annotated<Array<T>>> for Values<T> {
    fn from(values: Annotated<Array<T>>) -> Values<T> {
        Values {
            values,
            other: Map::new().into(),
        }
    }
}

impl<T> From<Array<T>> for Values<T> {
    fn from(values: Array<T>) -> Values<T> {
        Values::from(Annotated::from(values))
    }
}

impl<'de, T> Deserialize<'de> for Values<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr<T> {
            Qualified {
                values: Annotated<Array<T>>,
                #[serde(flatten)]
                other: Annotated<Map<Value>>,
            },
            Unqualified(Array<T>),
            Single(Annotated<T>),
        }

        Deserialize::deserialize(deserializer).map(|x| match x {
            Repr::Qualified { values, other } => Values { values, other },
            Repr::Unqualified(values) => values.into(),
            Repr::Single(value) => vec![value].into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_array() {
        let values = Values {
            values: vec![
                Value::from(1u64).into(),
                Value::from(2u64).into(),
                Value::from(3u64).into(),
            ].into(),
            other: Map::new().into(),
        };

        assert_eq_dbg!(values, serde_json::from_str("[1,2,3]").unwrap());
        assert_eq_str!(
            serde_json::to_string(&values).unwrap(),
            "{\"values\":[1,2,3]}"
        );
    }

    #[test]
    fn test_object() {
        let values = Values {
            values: vec![
                Value::from(1u64).into(),
                Value::from(2u64).into(),
                Value::from(3u64).into(),
            ].into(),
            other: Map::new().into(),
        };

        assert_eq_dbg!(
            values,
            serde_json::from_str("{\"values\":[1,2,3]}").unwrap()
        );

        assert_eq_str!(
            serde_json::to_string(&values).unwrap(),
            "{\"values\":[1,2,3]}"
        );
    }

    #[test]
    fn test_other() {
        let values = Values {
            values: vec![
                Value::from(1u64).into(),
                Value::from(2u64).into(),
                Value::from(3u64).into(),
            ].into(),
            other: {
                let mut m = Map::new();
                m.insert("foo".to_string(), Annotated::from(Value::from("bar")));
                Annotated::from(m)
            },
        };

        assert_eq_dbg!(
            values,
            serde_json::from_str("{\"values\":[1,2,3],\"foo\":\"bar\"}").unwrap()
        );

        assert_eq_str!(
            serde_json::to_string(&values).unwrap(),
            "{\"values\":[1,2,3],\"foo\":\"bar\"}"
        );
    }

    #[test]
    fn test_option() {
        assert_eq_dbg!(
            None,
            serde_json::from_str::<Option<Values<u32>>>("null").unwrap()
        );
    }

    #[test]
    fn test_empty() {
        assert!(Values::<u32>::new().is_empty());
        assert!(!Values::from(vec![1.into(), 2.into(), 3.into()]).is_empty())
    }
}
