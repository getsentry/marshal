use std::collections::BTreeMap;
use meta::Annotated;

#[derive(Debug, Clone)]
pub enum Value {
    Bool(bool),
    U32(u32),
    I32(i32),
    U64(u64),
    I64(i64),
    F32(f32),
    F64(f64),
    String(String),
    Array(Vec<Annotated<Value>>),
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
