//! Implements a processing system for the protocol.
use std::collections::BTreeMap;

use chunk::{self, Chunk};
use common::{Array, Map, Value};
use meta::{Annotated, Meta};

/// The type of PII that's contained in the field.
#[derive(Copy, Clone, Debug, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
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
#[derive(Clone, Debug, Default)]
pub struct ValueInfo {
    /// The type of PII info
    pub pii_kind: Option<PiiKind>,
    /// The size cap of the field
    pub cap: Option<Cap>,
}

impl ValueInfo {
    /// Derives a value info from the current one for unknown child elements.
    pub fn derive(&self) -> ValueInfo {
        ValueInfo {
            pii_kind: match self.pii_kind {
                Some(PiiKind::Databag) => Some(PiiKind::Databag),
                _ => None,
            },
            cap: match self.cap {
                Some(Cap::Databag) => Some(Cap::Databag),
                _ => None,
            },
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

    /// Processes an annotated `Value`.
    fn process_value(&self, annotated: Annotated<Value>, info: &ValueInfo) -> Annotated<Value> {
        match annotated {
            Annotated(Some(Value::Bool(val)), meta) => {
                let Annotated(val_opt, meta) = self.process_bool(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::Bool), meta)
            }
            Annotated(Some(Value::U32(val)), meta) => {
                let Annotated(val_opt, meta) = self.process_u32(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::U32), meta)
            }
            Annotated(Some(Value::I32(val)), meta) => {
                let Annotated(val_opt, meta) = self.process_i32(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::I32), meta)
            }
            Annotated(Some(Value::U64(val)), meta) => {
                let Annotated(val_opt, meta) = self.process_u64(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::U64), meta)
            }
            Annotated(Some(Value::I64(val)), meta) => {
                let Annotated(val_opt, meta) = self.process_i64(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::I64), meta)
            }
            Annotated(Some(Value::F32(val)), meta) => {
                let Annotated(val_opt, meta) = self.process_f32(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::F32), meta)
            }
            Annotated(Some(Value::F64(val)), meta) => {
                let Annotated(val_opt, meta) = self.process_f64(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::F64), meta)
            }
            Annotated(Some(Value::String(val)), meta) => {
                let Annotated(val_opt, meta) = self.process_string(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::String), meta)
            }
            Annotated(Some(Value::Array(val)), meta) => {
                let mut rv = Vec::with_capacity(val.len());
                for item in val.into_iter() {
                    rv.push(self.process_value(item, &info.derive()));
                }
                Annotated(Some(Value::Array(rv)), meta)
            }
            Annotated(Some(Value::Map(val)), meta) => {
                let mut rv = BTreeMap::new();
                for (key, value) in val.into_iter() {
                    let value = self.process_value(value, &info.derive());
                    rv.insert(key, value);
                }
                Annotated(Some(Value::Map(rv)), meta)
            }
            other @ Annotated(Some(Value::Null), _) => other,
            other @ Annotated(None, _) => other,
        }
    }
}

/// A trait implemented for annotated types that support processing.
pub trait ProcessAnnotatedValue {
    /// Processes an annotated value.
    fn process_annotated_value(
        annotated: Annotated<Self>,
        processor: &Processor,
        info: &ValueInfo,
    ) -> Annotated<Self>
    where
        Self: Sized;
}

/// Helper trait for pii processing.
pub trait PiiProcessor {
    /// Processes a string containing freeform data chunked.
    fn pii_process_freeform_chunks(&self, chunks: Vec<Chunk>, meta: Meta) -> (Vec<Chunk>, Meta) {
        (chunks, meta)
    }

    /// Processes a single value.
    ///
    /// The type of the value contained must not be changed.
    fn pii_process_value(&self, value: Annotated<Value>, kind: PiiKind) -> Annotated<Value> {
        let _kind = kind;
        value
    }
}

macro_rules! impl_primitive_pii_process {
    ($ty:ident, $value_ty:ident, $func:ident) => {
        fn $func(
            &self,
            annotated: Annotated<$ty>,
            info: &ValueInfo,
        ) -> Annotated<$ty> {
            match (annotated, info.pii_kind) {
                (annotated, None) | (annotated @ Annotated(None, _), _) => annotated,
                (Annotated(Some(value), meta), Some(pii_kind)) => {
                    let annotated = Annotated(Some(Value::$value_ty(value)), meta);
                    match self.pii_process_value(annotated, pii_kind) {
                        Annotated(Some(Value::$value_ty(value)), meta) => Annotated(Some(value), meta),
                        Annotated(_, meta) => Annotated(None, meta),
                    }
                }
            }
        }
    };
}

impl<T: PiiProcessor> Processor for T {
    fn process_string(&self, annotated: Annotated<String>, info: &ValueInfo) -> Annotated<String> {
        match (annotated, info.pii_kind) {
            (annotated, None) | (annotated @ Annotated(None, _), _) => annotated,
            (Annotated(Some(value), meta), Some(PiiKind::Freeform)) => {
                let original_length = value.len();
                let chunks = chunk::chunks_from_str(&value, &meta);
                let (chunks, meta) = PiiProcessor::pii_process_freeform_chunks(self, chunks, meta);
                let (value, mut meta) = chunk::chunks_to_string(chunks, meta);
                if value.len() != original_length && meta.original_length.is_none() {
                    meta.original_length = Some(original_length as u32);
                }
                Annotated(Some(value), meta)
            }
            (Annotated(Some(value), meta), Some(pii_kind)) => {
                let original_length = value.len();
                let annotated = Annotated(Some(Value::String(value)), meta);
                match self.pii_process_value(annotated, pii_kind) {
                    Annotated(Some(Value::String(value)), mut meta) => {
                        if value.len() != original_length && meta.original_length.is_none() {
                            meta.original_length = Some(original_length as u32);
                        }
                        Annotated(Some(value), meta)
                    }
                    Annotated(_, meta) => Annotated(None, meta),
                }
            }
        }
    }

    impl_primitive_pii_process!(bool, Bool, process_bool);
    impl_primitive_pii_process!(u32, U32, process_u32);
    impl_primitive_pii_process!(i32, I32, process_i32);
    impl_primitive_pii_process!(u64, U64, process_u64);
    impl_primitive_pii_process!(i64, I64, process_i64);
    impl_primitive_pii_process!(f32, F32, process_f32);
    impl_primitive_pii_process!(f64, F64, process_f64);
}

macro_rules! impl_primitive_process {
    ($ty:ident, $func:ident) => {
        impl ProcessAnnotatedValue for $ty {
            fn process_annotated_value(
                annotated: Annotated<$ty>,
                processor: &Processor,
                info: &ValueInfo,
            ) -> Annotated<$ty> {
                processor.$func(annotated, info)
            }
        }
    };
}

impl_primitive_process!(bool, process_bool);
impl_primitive_process!(u32, process_u32);
impl_primitive_process!(i32, process_i32);
impl_primitive_process!(u64, process_u64);
impl_primitive_process!(i64, process_i64);
impl_primitive_process!(f32, process_f32);
impl_primitive_process!(f64, process_f64);
impl_primitive_process!(String, process_string);
impl_primitive_process!(Value, process_value);

impl<T: ProcessAnnotatedValue> ProcessAnnotatedValue for Array<T> {
    fn process_annotated_value(
        annotated: Annotated<Self>,
        processor: &Processor,
        info: &ValueInfo,
    ) -> Annotated<Self> {
        annotated.map(|value| {
            value
                .into_iter()
                .map(|item| {
                    ProcessAnnotatedValue::process_annotated_value(item, processor, &info.derive())
                })
                .collect()
        })
    }
}

impl<T: ProcessAnnotatedValue> ProcessAnnotatedValue for Map<T> {
    fn process_annotated_value(
        annotated: Annotated<Self>,
        processor: &Processor,
        info: &ValueInfo,
    ) -> Annotated<Self> {
        annotated.map(|value| {
            value
                .into_iter()
                .map(|(key, value)| {
                    (
                        key,
                        ProcessAnnotatedValue::process_annotated_value(
                            value,
                            processor,
                            &info.derive(),
                        ),
                    )
                })
                .collect()
        })
    }
}

#[test]
fn test_basic_processing() {
    #[derive(ProcessAnnotatedValue)]
    struct Event {
        flag: bool,
        #[process_annotated_value]
        id: Annotated<u32>,
        #[process_annotated_value(pii_kind = "freeform", cap = "message")]
        message: Annotated<String>,
    }

    struct MyProcessor;

    impl Processor for MyProcessor {
        fn process_u32(&self, mut annotated: Annotated<u32>, _info: &ValueInfo) -> Annotated<u32> {
            annotated.set_value(None);
            annotated.meta_mut().errors.push("Whatever mate".into());
            annotated
        }
    }

    let event = Annotated::from(Event {
        flag: true,
        id: Annotated::from(42),
        message: Annotated::from("Hello World!".to_string()),
    });

    let new_event =
        ProcessAnnotatedValue::process_annotated_value(event, &MyProcessor, &ValueInfo::default());
    let id = new_event.0.unwrap().id;
    assert!(id.value().is_none());
    assert_eq!(&id.meta().errors[0], "Whatever mate");
}

#[test]
fn test_pii_processing() {
    use meta::Note;

    #[derive(ProcessAnnotatedValue)]
    struct Event {
        flag: bool,
        #[process_annotated_value(pii_kind = "id")]
        id: Annotated<u32>,
        #[process_annotated_value(pii_kind = "freeform")]
        message: Annotated<String>,
    }

    struct MyPiiProcessor;

    impl PiiProcessor for MyPiiProcessor {
        fn pii_process_value(
            &self,
            annotated: Annotated<Value>,
            pii_kind: PiiKind,
        ) -> Annotated<Value> {
            use meta::Remark;
            match (annotated, pii_kind) {
                (annotated, PiiKind::Id) => {
                    annotated.with_removed_value(Remark::well_known("@id-removed"))
                }
                (annotated, _) => annotated,
            }
        }
    }

    let event = Annotated::from(Event {
        flag: true,
        id: Annotated::from(42),
        message: Annotated::from("Hello World!".to_string()),
    });

    let new_event = ProcessAnnotatedValue::process_annotated_value(
        event,
        &MyPiiProcessor,
        &ValueInfo::default(),
    );
    let id = new_event.0.unwrap().id;
    assert!(id.value().is_none());
    assert_eq!(
        id.meta().remarks().next().unwrap().note(),
        &Note::well_known("@id-removed")
    );
}
