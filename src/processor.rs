use std::collections::HashMap;

use meta::Annotated;

/// The type of PII that's contained in the field.
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

/// Information about how to process PII in the field.
pub struct PiiInfo {
    pub pii_kind: Option<PiiKind>,
}

impl PiiInfo {
    pub fn derive(&self) -> PiiInfo {
        PiiInfo {
            pii_kind: match self.pii_kind {
                Some(PiiKind::DataBag) => Some(PiiKind::DataBag),
                _ => None,
            },
        }
    }
}

macro_rules! declare_primitive_process {
    ($ty:ident, $func:ident) => {
        fn $func(&self, annotated: &mut Annotated<$ty>, info: &PiiInfo);
    }
}

macro_rules! impl_primitive_process {
    ($ty:ident, $func:ident) => {
        impl PiiProcess for $ty {
            fn pii_process(annotated: &mut Annotated<$ty>, processor: &PiiProcessor, info: &PiiInfo) {
                processor.$func(annotated, info);
            }
        }
    }
}

pub trait PiiProcessor {
    declare_primitive_process!(bool, process_bool);
    declare_primitive_process!(u32, process_u32);
    declare_primitive_process!(i32, process_i32);
    declare_primitive_process!(u64, process_u64);
    declare_primitive_process!(i64, process_i64);
    declare_primitive_process!(f32, process_f32);
    declare_primitive_process!(f64, process_f64);
    declare_primitive_process!(String, process_string);
}

pub trait PiiProcess {
    fn pii_process(annotated: &mut Annotated<Self>, processor: &PiiProcessor, info: &PiiInfo)
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

#[derive(PiiProcess)]
struct TestEvent {
    id: Annotated<u32>,
    #[pii_process(pii_kind = "freeform")]
    message: Annotated<String>,
}
