use std::collections::BTreeMap;

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

impl ProcessValue for Value {
    fn process_value(annotated: Annotated<Self>, processor: &Processor, info: &ValueInfo) -> Annotated<Self> {
        match annotated {
            Annotated(Some(Value::Bool(val)), meta) => {
                let Annotated(val_opt, meta) = processor.process_bool(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::Bool), meta)
            }
            Annotated(Some(Value::U32(val)), meta) => {
                let Annotated(val_opt, meta) = processor.process_u32(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::U32), meta)
            }
            Annotated(Some(Value::I32(val)), meta) => {
                let Annotated(val_opt, meta) = processor.process_i32(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::I32), meta)
            }
            Annotated(Some(Value::U64(val)), meta) => {
                let Annotated(val_opt, meta) = processor.process_u64(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::U64), meta)
            }
            Annotated(Some(Value::I64(val)), meta) => {
                let Annotated(val_opt, meta) = processor.process_i64(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::I64), meta)
            }
            Annotated(Some(Value::F32(val)), meta) => {
                let Annotated(val_opt, meta) = processor.process_f32(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::F32), meta)
            }
            Annotated(Some(Value::F64(val)), meta) => {
                let Annotated(val_opt, meta) = processor.process_f64(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::F64), meta)
            }
            Annotated(Some(Value::String(val)), meta) => {
                let Annotated(val_opt, meta) = processor.process_string(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::String), meta)
            }
            Annotated(Some(Value::Array(val)), meta) => {
                let mut rv = Vec::with_capacity(val.len());
                for item in val.into_iter() {
                    rv.push(ProcessValue::process_value(
                        item,
                        processor,
                        &info.derive()
                    ));
                }
                Annotated(Some(Value::Array(rv)), meta)
            }
            Annotated(Some(Value::Map(val)), meta) => {
                let mut rv = BTreeMap::new();
                for (key, value) in val.into_iter() {
                    rv.insert(key, ProcessValue::process_value(
                        value,
                        processor,
                        &info.derive()
                    ));
                }
                Annotated(Some(Value::Map(rv)), meta)
            }
            other @ Annotated(None, _) => other,
        }
    }
}

#[derive(ProcessValue)]
struct TestEvent {
    flag: bool,
    #[process_value]
    id: Annotated<u32>,
    #[process_value(pii_kind = "freeform", cap = "message")]
    message: Annotated<String>,
}
