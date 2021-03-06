//! Implements a processing system for the protocol.
use std::collections::BTreeMap;

use protocol::{Annotated, Array, Map, Meta, Value, Values};

use super::chunks::{self, Chunk};

macro_rules! define_pii_kind {
    ($($variant:ident($str:expr) : $doc:expr;)*) => {
        /// The type of PII that's contained in the field.
        #[derive(Copy, Clone, Debug, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
        #[serde(rename_all = "snake_case")]
        pub enum PiiKind {
            $(
                #[doc=$doc]
                $variant,
            )*
        }

        /// Names of all PII kinds
        pub static PII_KINDS: &[&'static str] = &[
            $($str),*
        ];
    }
}

define_pii_kind! {
    Freeform("freeform"): "A freeform text potentially containing PII data.";
    Ip("ip"): "An ip address";
    Id("id"): "A user, unique device or other PII ID";
    Username("username"): "A username or other user identifier";
    Hostname("hostname"): "Hostname of a machine (server, pc or mobile device).";
    Sensitive("sensitive"): "Sensitive PII if they ever come up in the protocol (gender, religious orientation etc.)";
    Name("name"): "First, last or real name of a person";
    Email("email"): "An email address";
    Location("location"): "Geographical location information.";
    Databag("databag"): "An arbitrary structured data bag";
}

/// The type of cap applied to the value.
#[derive(Copy, Clone, Debug)]
pub enum Cap {
    /// A summary text.
    Summary,
    /// A message text.
    Message,
    /// A path.
    Path,
    /// A short path (typically just filename).
    ShortPath,
    /// An arbirtrary object with nested data.
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
    declare_primitive_process!(u64, process_u64);
    declare_primitive_process!(i64, process_i64);
    declare_primitive_process!(f64, process_f64);
    declare_primitive_process!(String, process_string);

    /// Processes an annotated `Value`.
    fn process_value(&self, annotated: Annotated<Value>, info: &ValueInfo) -> Annotated<Value> {
        match annotated {
            Annotated(Some(Value::Bool(val)), meta) => {
                let Annotated(val_opt, meta) = self.process_bool(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::Bool), meta)
            }
            Annotated(Some(Value::U64(val)), meta) => {
                let Annotated(val_opt, meta) = self.process_u64(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::U64), meta)
            }
            Annotated(Some(Value::I64(val)), meta) => {
                let Annotated(val_opt, meta) = self.process_i64(Annotated::new(val, meta), info);
                Annotated(val_opt.map(Value::I64), meta)
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
                for item in val {
                    rv.push(self.process_value(item, &info.derive()));
                }
                Annotated(Some(Value::Array(rv)), meta)
            }
            Annotated(Some(Value::Map(val)), meta) => {
                let mut rv = BTreeMap::new();
                for (key, value) in val {
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
    /// This is invoked with chunked data for strings.
    ///
    /// If the PII processor returns `Ok` then a modification is recorded.  If an
    /// `Err` is returned then the regular `pii_process_value` is invoked as a
    /// fallback.
    fn pii_process_chunks(
        &self,
        chunks: Vec<Chunk>,
        meta: Meta,
        pii_kind: PiiKind,
    ) -> Result<(Vec<Chunk>, Meta), (Vec<Chunk>, Meta)> {
        let _pii_kind = pii_kind;
        Err((chunks, meta))
    }

    /// Processes a single value.
    ///
    /// The type of the value contained should not be changed as the processor is
    /// unlikely to know if a value of a different type is accepted.  If a value
    /// of an invalid type is emitted it's changed to null.
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
                    let annotated = Annotated(Some(Value::$value_ty(value.into())), meta);
                    match self.pii_process_value(annotated, pii_kind) {
                        Annotated(Some(Value::$value_ty(value)), meta) => Annotated(Some(value as $ty), meta),
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
            (Annotated(Some(value), meta), Some(pii_kind)) => {
                let original_length = value.len();

                match self.pii_process_value(Annotated(Some(Value::String(value)), meta), pii_kind)
                {
                    Annotated(Some(Value::String(value)), mut meta) => {
                        let (value, mut meta) = {
                            let chunks = chunks::split(&value, meta.remarks());
                            match self.pii_process_chunks(chunks, meta, pii_kind) {
                                Ok((chunks, mut meta)) => {
                                    let (value, remarks) = chunks::join(chunks);
                                    *meta.remarks_mut() = remarks;
                                    (value, meta)
                                }
                                Err((_, meta)) => (value, meta),
                            }
                        };

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
    impl_primitive_pii_process!(u64, U64, process_u64);
    impl_primitive_pii_process!(i64, I64, process_i64);
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
                processor
                    .$func(annotated.map(From::from), info)
                    .map(|x| x as $ty)
            }
        }
    };
}

impl_primitive_process!(bool, process_bool);
impl_primitive_process!(u32, process_u64);
impl_primitive_process!(i32, process_i64);
impl_primitive_process!(u64, process_u64);
impl_primitive_process!(i64, process_i64);
impl_primitive_process!(f32, process_f64);
impl_primitive_process!(f64, process_f64);
impl_primitive_process!(String, process_string);
impl_primitive_process!(Value, process_value);

impl<T: ProcessAnnotatedValue> ProcessAnnotatedValue for Option<T> {
    fn process_annotated_value(
        annotated: Annotated<Self>,
        processor: &Processor,
        info: &ValueInfo,
    ) -> Annotated<Self> {
        match annotated {
            Annotated(Some(Some(value)), meta) => ProcessAnnotatedValue::process_annotated_value(
                Annotated::new(value, meta),
                processor,
                info,
            ).map(Some),
            other @ Annotated(Some(None), _) => other,
            other @ Annotated(None, _) => other,
        }
    }
}

impl<T: ProcessAnnotatedValue> ProcessAnnotatedValue for Box<T> {
    fn process_annotated_value(
        annotated: Annotated<Self>,
        processor: &Processor,
        info: &ValueInfo,
    ) -> Annotated<Self> {
        match annotated {
            Annotated(Some(value), meta) => ProcessAnnotatedValue::process_annotated_value(
                Annotated::new(*value, meta),
                processor,
                info,
            ).map(Box::new),
            other @ Annotated(None, _) => other,
        }
    }
}

impl<T: ProcessAnnotatedValue> ProcessAnnotatedValue for Values<T> {
    fn process_annotated_value(
        annotated: Annotated<Self>,
        processor: &Processor,
        info: &ValueInfo,
    ) -> Annotated<Self> {
        annotated.map(|Values { values, other }| Values {
            values: ProcessAnnotatedValue::process_annotated_value(
                values,
                processor,
                &info.derive(),
            ),
            other: ProcessAnnotatedValue::process_annotated_value(other, processor, &info.derive()),
        })
    }
}

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
                }).collect()
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
                }).collect()
        })
    }
}

// TODO: Move these tests to /tests
#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{Remark, RemarkType};

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
            fn process_u64(
                &self,
                mut annotated: Annotated<u64>,
                _info: &ValueInfo,
            ) -> Annotated<u64> {
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

        let new_event = ProcessAnnotatedValue::process_annotated_value(
            event,
            &MyProcessor,
            &ValueInfo::default(),
        );
        let id = new_event.0.unwrap().id;
        assert_eq_dbg!(id, Annotated::from_error("Whatever mate"));
    }

    #[test]
    fn test_pii_processing() {
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
                match (annotated, pii_kind) {
                    (annotated, PiiKind::Id) => annotated
                        .with_removed_value(Remark::new(RemarkType::Removed, "@id-removed")),
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
        assert_eq_str!(id.meta().remarks().next().unwrap().rule_id(), "@id-removed");
    }
}
