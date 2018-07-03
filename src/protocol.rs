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
#[derive(Debug, Deserialize, PartialEq)]
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
