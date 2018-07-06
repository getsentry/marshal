use std::collections::HashMap;

use meta::Annotated;

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
    DataBag,
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

/// Information about how to process PII in the field.
#[derive(Clone, Debug)]
pub struct ValueInfo {
    pub pii_kind: Option<PiiKind>,
    pub cap: Cap,
}

impl ValueInfo {
    pub fn derive(&self) -> ValueInfo {
        ValueInfo {
            pii_kind: match self.pii_kind {
                Some(PiiKind::DataBag) => Some(PiiKind::DataBag),
                _ => None,
            },
            cap: self.cap,
        }
    }
}

macro_rules! declare_primitive_process {
    ($ty:ident, $func:ident) => {
        fn $func(&self, annotated: &mut Annotated<$ty>, info: &ValueInfo);
    }
}

macro_rules! impl_primitive_process {
    ($ty:ident, $func:ident) => {
        impl ProcessValue for $ty {
            fn process_value(annotated: &mut Annotated<$ty>, processor: &Processor, info: &ValueInfo) {
                processor.$func(annotated, info);
            }
        }
    }
}

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

pub trait ProcessValue {
    fn process_value(annotated: &mut Annotated<Self>, processor: &Processor, info: &ValueInfo)
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

#[derive(ProcessValue)]
struct TestEvent {
    id: Annotated<u32>,
    #[process_value(pii_kind = "freeform", cap = "message")]
    message: Annotated<String>,
}
