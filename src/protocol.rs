//! The current latest sentry protocol version.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use common::Values;
use meta::{self, Annotated, MetaMap, MetaTree};
use utils::buffer::{Content, ContentDeserializer, ContentRefDeserializer};
use utils::{annotated, serde_chrono};

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
    #[serde(default = "default_breadcrumb_type", rename = "type")]
    pub ty: Annotated<String>,

    /// The optional category of the breadcrumb.
    #[serde(default, skip_serializing_if = "annotated::is_none")]
    pub category: Annotated<Option<String>>,
}

#[cfg(test)]
mod test_breadcrumb {
    use super::*;
    use serde_json;

    #[test]
    fn test_roundtrip() {
        let json = r#"{
  "timestamp": 42,
  "type": "mytype",
  "category": "mycategory"
}"#;

        let breadcrumb = Annotated::from(Breadcrumb {
            timestamp: serde_chrono::timestamp_to_datetime(42.0).into(),
            ty: "mytype".to_string().into(),
            category: Some("mycategory".to_string()).into(),
        });

        assert_eq!(breadcrumb, serde_json::from_str(json).unwrap());
        assert_eq!(json, &serde_json::to_string_pretty(&breadcrumb).unwrap());
    }

    #[test]
    fn test_default_values() {
        let input = r#"{"timestamp":42}"#;
        let output = r#"{"timestamp":42,"type":"default"}"#;

        let breadcrumb = Annotated::from(Breadcrumb {
            timestamp: serde_chrono::timestamp_to_datetime(42.0).into(),
            ty: default_breadcrumb_type(),
            category: None.into(),
        });

        assert_eq!(breadcrumb, serde_json::from_str(input).unwrap());
        assert_eq!(output, &serde_json::to_string(&breadcrumb).unwrap());
    }
}

/// Represents a full event for Sentry.
#[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct Event {
    /// The unique identifier of this event.
    #[serde(default, rename = "event_id", skip_serializing_if = "annotated::is_none")]
    pub id: Annotated<Option<Uuid>>,

    /// List of breadcrumbs recorded before this event.
    #[serde(default, skip_serializing_if = "annotated::is_empty_values")]
    pub breadcrumbs: Annotated<Values<Annotated<Breadcrumb>>>,
}

#[derive(Debug, Deserialize)]
struct EventMetaDeserializeHelper {
    metadata: Option<MetaMap>,
}

/// Deserializes an annotated event with meta data from the given deserializer.
pub fn deserialize_event<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Annotated<Event>, D::Error> {
    let content = Content::deserialize(deserializer)?;
    let helper = EventMetaDeserializeHelper::deserialize(ContentRefDeserializer::new(&content))?;
    let meta_map = helper.metadata.unwrap_or_default();
    meta::deserialize(ContentDeserializer::new(content), meta_map)
}

#[derive(Debug, Serialize)]
struct EventMetaSerializeHelper<'a> {
    #[serde(flatten)]
    event: Option<&'a Event>,
    metadata: MetaTree,
}

/// Serializes an event and its meta data into the given serializer.
pub fn serialize_event<S: Serializer>(
    event: &Annotated<Event>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::Error;
    EventMetaSerializeHelper {
        event: event.value(),
        metadata: meta::serialize_meta(event).map_err(S::Error::custom)?,
    }.serialize(serializer)
}

#[cfg(test)]
mod test_event {
    use super::*;
    use meta::Meta;
    use serde_json;

    fn serialize(event: &Annotated<Event>) -> Result<String, serde_json::Error> {
        let mut serializer = serde_json::Serializer::pretty(Vec::new());
        serialize_event(event, &mut serializer)?;
        Ok(String::from_utf8(serializer.into_inner()).unwrap())
    }

    fn deserialize(string: &str) -> Result<Annotated<Event>, serde_json::Error> {
        deserialize_event(&mut serde_json::Deserializer::from_str(string))
    }

    #[test]
    fn test_roundtrip() {
        // NOTE: Interfaces will be tested separately.
        let json = r#"{
  "event_id": "52df9022-8352-46ee-b317-dbd739ccd059",
  "metadata": {
    "event_id": {
      "": {
        "errors": [
          "some error"
        ]
      }
    }
  }
}"#;

        let event = Annotated::from(Event {
            id: Annotated::new(
                Some("52df9022-8352-46ee-b317-dbd739ccd059".parse().unwrap()),
                Meta::from_error("some error"),
            ),
            breadcrumbs: Default::default(),
        });

        assert_eq!(event, deserialize(json).unwrap());
        assert_eq!(json, serialize(&event).unwrap());
    }

    #[test]
    fn test_default_values() {
        let json = r#"{"event_id":"52df9022-8352-46ee-b317-dbd739ccd059"}"#;
        let event = Annotated::from(Event {
            id: Some("52df9022-8352-46ee-b317-dbd739ccd059".parse().unwrap()).into(),
            breadcrumbs: Default::default(),
        });

        assert_eq!(event, serde_json::from_str(json).unwrap());
        assert_eq!(json, &serde_json::to_string(&event).unwrap());
    }

    #[test]
    fn test_invalid() {
        let json = r#"{
  "event_id": null,
  "metadata": {
    "event_id": {
      "": {
        "errors": [
          "some error"
        ]
      }
    }
  }
}"#;

        let event = Annotated::from(Event {
            id: Annotated::from_error("some error"),
            breadcrumbs: Default::default(),
        });

        assert_eq!(event, deserialize(json).unwrap());
        assert_eq!(json, serialize(&event).unwrap());
    }
}
