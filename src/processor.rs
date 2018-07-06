use std::collections::HashMap;

use meta::Annotated;
use value::Value;

/// The type of PII that's contained in the field.
#[derive(Copy, Clone, Debug)]
pub enum PiiKind {
    /// A freeform text potentially containing PII data.
    Freeform,
    /// An ip address
    Ip,
    /// A user, unique device or other PII ID
    Id,
    /// A username or other user identifier
    Username,
    /// Sensitive PII if they ever come up in the protocol (gender, religious orientation etc.)
    Sensitive,
    /// First, last or real name of a person
    Name,
    /// An email address
    Email,
    /// An arbitrary structured data bag
    Databag,
}

/// The type of cap applied to the value.
#[derive(Copy, Clone, Debug)]
pub enum Cap {
    /// A summary text
    Summary,
    /// A message text
    Message,
    /// A path
    Path,
    /// A short path (typically just filename)
    ShortPath,
    /// Default limits for databags
    Databag,
}

/// Information about how to process certain annotated values.
#[derive(Clone, Debug)]
pub struct ValueInfo {
    pub pii_kind: Option<PiiKind>,
    pub cap: Option<Cap>,
}

impl ValueInfo {
    pub fn derive(&self) -> ValueInfo {
        ValueInfo {
            pii_kind: match self.pii_kind {
                Some(PiiKind::Databag) => Some(PiiKind::Databag),
                _ => None,
            },
            cap: match self.cap {
                Some(Cap::Databag) => Some(Cap::Databag),
                _ => None,
            }
        }
    }
}

macro_rules! declare_primitive_process {
    ($ty:ident, $func:ident) => {
        declare_primitive_process!($ty, $func, stringify!($ty));
    };
    ($ty:ident, $func:ident, $help_ty:expr) => {
        #[doc = "Processes an annotated value of type `"]
        #[doc = $help_ty]
        #[doc = "`."]
        fn $func(&self, annotated: Annotated<$ty>, info: &ValueInfo) -> Annotated<$ty> {
            let _info = info;
            annotated
        }
    }
}

macro_rules! impl_primitive_process {
    ($ty:ident, $func:ident) => {
        impl ProcessValue for $ty {
            fn process_value(annotated: Annotated<$ty>, processor: &Processor, info: &ValueInfo) -> Annotated<$ty> {
                processor.$func(annotated, info)
            }
        }
    }
}

/// A general processing trait for annotated values.
pub trait Processor {
    declare_primitive_process!(bool, process_bool);
    declare_primitive_process!(u32, process_u32);
    declare_primitive_process!(i32, process_i32);
    declare_primitive_process!(u64, process_u64);
    declare_primitive_process!(i64, process_i64);
    declare_primitive_process!(f32, process_f32);
    declare_primitive_process!(f64, process_f64);
    declare_primitive_process!(String, process_string);
}

/// A trait implemented for annotated types that support processing.
pub trait ProcessValue {
    fn process_value(annotated: Annotated<Self>, processor: &Processor, info: &ValueInfo) -> Annotated<Self>
    where
        Self: Sized;
}

impl_primitive_process!(bool, process_bool);
impl_primitive_process!(u32, process_u32);
impl_primitive_process!(i32, process_i32);
impl_primitive_process!(u64, process_u64);
impl_primitive_process!(i64, process_i64);
impl_primitive_process!(f32, process_f32);
impl_primitive_process!(f64, process_f64);
impl_primitive_process!(String, process_string);

impl<T: ProcessValue> ProcessValue for Vec<Annotated<T>> {
    fn process_value(annotated: Annotated<Self>, processor: &Processor, info: &ValueInfo) -> Annotated<Self> {
        annotated.map(|value| {
            value
                .into_iter()
                .map(|item| ProcessValue::process_value(item, processor, &info.derive()))
                .collect()
        })
    }
}

/*
impl ProcessValue for Value {
    fn process_value(annotated: Annotated<Self>, processor: &Processor, info: &ValueInfo) -> Annotated<Self> {
        if let Some(value) = annotated.value_mut() {
            match value {
                Value::U32(value) => {
                    let rv = processor.process_u32(Annotated::from(value), info);
                    Annotated::new(rv.take.map(Value::U32), rv.take_meta())
                }
                _ => unreachable!()
            }
        }
    }
}

#[derive(ProcessValue)]
struct TestEvent {
    #[process_value]
    id: Annotated<u32>,
    #[process_value(pii_kind = "freeform", cap = "message")]
    message: Annotated<String>,
}
*/
