//! The current latest sentry protocol version.

use chrono::{DateTime, Utc};
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
    fn test_default_type() {
        let breadcrumb = Breadcrumb {
            timestamp: serde_chrono::timestamp_to_datetime(47.11).into(),
            ty: default_breadcrumb_type(),
            category: None.into(),
        };

        assert_eq!(
            Annotated::from(breadcrumb),
            serde_json::from_str(r#"{"timestamp": 47.11}"#).unwrap()
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
