//! Common data structures.

use std::iter::FromIterator;
use std::ops;

use serde::de::{Deserialize, Deserializer};

use serde_json::value::{Map, Value};

/// A wrapper type for collections with attached meta data.
///
/// The JSON payload can either directly be an array or an object containing a `values` field and
/// arbitrary other fields. All other fields will be collected into `Values::data` when
/// deserializing and re-serialized in the same place. The shorthand array notation is always
/// reserialized as object.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Values<T> {
    /// The values of the collection.
    pub values: Vec<T>,
    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten, default)]
    pub other: Map<String, Value>,
}

impl<T> Values<T> {
    /// Creates an empty values struct.
    pub fn new() -> Values<T> {
        Values {
            values: Vec::new(),
            other: Map::new(),
        }
    }

    /// Checks whether this struct is empty in both values and data.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty() && self.other.is_empty()
    }
}

impl<T> Default for Values<T> {
    fn default() -> Values<T> {
        // Default implemented manually even if <T> does not impl Default.
        Values::new()
    }
}

impl<T> From<Vec<T>> for Values<T> {
    fn from(values: Vec<T>) -> Values<T> {
        Values {
            values,
            other: Map::new(),
        }
    }
}

impl<T> ops::Deref for Values<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl<T> ops::DerefMut for Values<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}

impl<T> FromIterator<T> for Values<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Vec::<T>::from_iter(iter).into()
    }
}

impl<T> Extend<T> for Values<T> {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = T>,
    {
        self.values.extend(iter)
    }
}

impl<'a, T> IntoIterator for &'a mut Values<T> {
    type Item = <&'a mut Vec<T> as IntoIterator>::Item;
    type IntoIter = <&'a mut Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&mut self.values).into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Values<T> {
    type Item = <&'a Vec<T> as IntoIterator>::Item;
    type IntoIter = <&'a Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&self.values).into_iter()
    }
}

impl<T> IntoIterator for Values<T> {
    type Item = <Vec<T> as IntoIterator>::Item;
    type IntoIter = <Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
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
                values: Vec<T>,
                #[serde(flatten)]
                other: Map<String, Value>,
            },
            Unqualified(Vec<T>),
            Single(T),
        }

        Deserialize::deserialize(deserializer).map(|x| match x {
            Repr::Qualified { values, other } => Values { values, other },
            Repr::Unqualified(values) => values.into(),
            Repr::Single(value) => vec![value].into(),
        })
    }
}

#[cfg(test)]
mod test_values {
    use super::*;

    use serde_json;

    #[test]
    fn test_array() {
        let values = Values {
            values: vec![1, 2, 3],
            other: Map::new(),
        };

        assert_eq!(values, serde_json::from_str("[1,2,3]").unwrap());
        assert_eq!(
            serde_json::to_string(&values).unwrap(),
            "{\"values\":[1,2,3]}".to_string()
        );
    }

    #[test]
    fn test_object() {
        let values = Values {
            values: vec![1, 2, 3],
            other: Map::new(),
        };

        assert_eq!(
            values,
            serde_json::from_str("{\"values\":[1,2,3]}").unwrap()
        );

        assert_eq!(
            serde_json::to_string(&values).unwrap(),
            "{\"values\":[1,2,3]}".to_string()
        );
    }

    #[test]
    fn test_other() {
        let values = Values {
            values: vec![1, 2, 3],
            other: {
                let mut m = Map::new();
                m.insert("foo".into(), "bar".into());
                m
            },
        };

        assert_eq!(
            values,
            serde_json::from_str("{\"values\":[1,2,3],\"foo\":\"bar\"}").unwrap()
        );

        assert_eq!(
            serde_json::to_string(&values).unwrap(),
            "{\"values\":[1,2,3],\"foo\":\"bar\"}".to_string()
        );
    }

    #[test]
    fn test_option() {
        assert_eq!(
            None,
            serde_json::from_str::<Option<Values<u32>>>("null").unwrap()
        );
    }

    #[test]
    fn test_empty() {
        assert!(Values::<u32>::new().is_empty());
        assert!(!Values::from(vec![1, 2, 3]).is_empty())
    }
}
