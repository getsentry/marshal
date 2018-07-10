//! Implements an arbitrary type object for the protocol.
use meta::Annotated;
use std::collections::BTreeMap;

/// Holds an arbitrary type supported by the protocol.
#[derive(Debug, Clone)]
pub enum Value {
    /// A boolean vlaue.
    Bool(bool),
    /// An unsigned int 32
    U32(u32),
    /// A signed int 32
    I32(i32),
    /// An unsigned int 64
    U64(u64),
    /// A signed int 64
    I64(i64),
    /// A 32bit float
    F32(f32),
    /// A 64bit float
    F64(f64),
    /// A string
    String(String),
    /// An array of annotated values
    Array(Vec<Annotated<Value>>),
    /// A map of annotated values
    Map(BTreeMap<String, Annotated<Value>>),
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
