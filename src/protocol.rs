//! The current latest sentry protocol version.
use std::any::Any;

use meta::Meta;

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

use common::Values;
use meta::Annotated;
use utils::serde_chrono;

fn default_breadcrumb_type() -> Annotated<String> {
    "default".to_string().into()
}

/// A breadcrumb.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Breadcrumb {
    /// The timestamp of the breadcrumb (required).
    #[serde(with = "serde_chrono")]
    pub timestamp: Annotated<DateTime<Utc>>,

    /// The type of the breadcrumb.
    #[serde(default = "default_breadcrumb_type")]
    pub ty: Annotated<String>,

    /// The optional category of the breadcrumb.
    #[serde(default)]
    pub category: Annotated<Option<String>>,
}

#[cfg(test)]
mod test_breadcrumb {
    use super::*;
    use serde_json;
    use tests::assert_roundtrip;

    #[test]
    fn test_roundtrip() {
        let breadcrumb = Breadcrumb {
            timestamp: serde_chrono::timestamp_to_datetime(47.11).into(),
            ty: "mytype".to_string().into(),
            category: Some("mycategory".to_string()).into(),
        };

        assert_roundtrip(&breadcrumb);
    }

    // TODO: Test errors

    #[test]
    fn test_default_values() {
        let json = r#"{"timestamp": 47.11}"#;

        let breadcrumb = Breadcrumb {
            timestamp: serde_chrono::timestamp_to_datetime(47.11).into(),
            ty: default_breadcrumb_type(),
            category: None.into(),
        };

        assert_eq!(
            Annotated::from(breadcrumb),
            serde_json::from_str(json).unwrap()
        );
    }
}

/// Represents a full event for Sentry.
#[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct Event {
    /// The unique identifier of this event.
    #[serde(default, rename = "event_id")]
    pub id: Annotated<Option<Uuid>>,

    /// List of breadcrumbs recorded before this event.
    #[serde(default)]
    pub breadcrumbs: Annotated<Values<Annotated<Breadcrumb>>>,
}

#[cfg(test)]
mod test_event {
    use super::*;
    use tests::assert_roundtrip;

    #[test]
    fn test_roundtrip() {
        let event = Event {
            id: Some(Uuid::new_v4()).into(),
            breadcrumbs: Values::new().into(),
        };

        assert_roundtrip(&event);
    }

    // TODO: Test errors
}

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

pub struct ProcessInfo {
    pub pii_kind: Option<PiiKind>,
}

impl ProcessInfo {
    pub fn derive(&self) -> ProcessInfo {
        ProcessInfo {
            pii_kind: match self.pii_kind {
                Some(PiiKind::DataBag) => Some(PiiKind::DataBag),
                _ => None,
            },
        }
    }
}

trait Processor {
    fn process_string(annotated: &mut Annotated<String>, info: &ProcessInfo) {}
    fn process_u32(annotated: &mut Annotated<u32>, info: &ProcessInfo) {}
}

pub trait ProcessItem {
    fn process_item(annotated: &mut Annotated<Self>, processor: &Processor, info: &ProcessInfo)
    where
        Self: Sized;
}

impl<V> ProcessItem for HashMap<String, Annotated<V>>
where
    V: ProcessItem,
{
    fn process_item(annotated: &mut Annotated<Self>, processor: &Processor, info: &ProcessInfo) {
        for (_key, value) in annotated.value_mut().iter_mut() {
            ProcessItem::process_item(value, processor, &info.derive());
        }
    }
}

impl ProcessItem for String {
    fn process_item(annotated: &mut Annotated<Self>, processor: &Processor, info: &ProcessInfo) {
        processor.process_string(annotated, info);
    }
}

impl ProcessItem for u32 {
    fn process_item(annotated: &mut Annotated<Self>, processor: &Processor, info: &ProcessInfo) {
        processor.process_u32(annotated, info);
    }
}

#[derive(ProcessItem)]
struct TestEvent {
    id: Annotated<u32>,
    #[process_item(pii_kind = "freeform")]
    message: Annotated<String>,
    #[process_item(pii_kind = "databag")]
    extra: Annotated<::std::collections::HashMap<String, Annotated<String>>>,
}
