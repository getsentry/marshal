//! The current latest sentry protocol version.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use common::Values;
use meta::Annotated;
use utils::serde_chrono;

/// A breadcrumb.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Breadcrumb {
    /// The timestamp of the breadcrumb (required).
    #[serde(with = "serde_chrono")]
    pub timestamp: Annotated<DateTime<Utc>>,
    /// The type of the breadcrumb.
    pub ty: Annotated<String>,
    /// The optional category of the breadcrumb.
    pub category: Annotated<Option<String>>,
}

impl Default for Breadcrumb {
    fn default() -> Self {
        // TODO: Implement defaults properly
        Breadcrumb {
            timestamp: Utc::now().into(),
            ty: "default".to_string().into(),
            category: None.into(),
        }
    }
}

/// Represents a full event for Sentry.
#[derive(Debug, Default, Deserialize)]
pub struct Event {
    /// The unique identifier of this event.
    #[serde(default, rename = "event_id")]
    pub id: Annotated<Option<Uuid>>,
    /// List of breadcrumbs recorded before this event.
    #[serde(default)]
    pub breadcrumbs: Annotated<Values<Annotated<Breadcrumb>>>,
}
