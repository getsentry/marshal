use std::fmt;

use serde::{de::DeserializeOwned, Serialize};
use serde_json;

pub fn assert_roundtrip<T>(value: &T)
where
    T: Serialize + DeserializeOwned + fmt::Debug + PartialEq,
{
    let json = serde_json::to_string(value).unwrap();
    let result: T = serde_json::from_str(&json).unwrap();
    assert_eq!(&result, value);
}
