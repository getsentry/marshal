//! The current latest sentry protocol version.

use std::{fmt, str};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json;
use uuid::Uuid;

use common::{Map, Value, Values};
use meta::{self, Annotated, MetaMap, MetaTree};
use utils::buffer::{Content, ContentDeserializer, ContentRefDeserializer};
use utils::{annotated, serde_chrono};

fn default_breadcrumb_type() -> Annotated<String> {
    "default".to_string().into()
}

/// An error used when parsing `Level`.
#[derive(Debug, Fail)]
#[fail(display = "invalid level")]
pub struct ParseLevelError;

/// Severity level of an event or breadcrumb.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Indicates very spammy debug information.
    Debug,
    /// Informational messages.
    Info,
    /// A warning.
    Warning,
    /// An error.
    Error,
    /// Similar to error but indicates a critical event that usually causes a shutdown.
    Fatal,
}

impl Default for Level {
    fn default() -> Level {
        Level::Info
    }
}

impl str::FromStr for Level {
    type Err = ParseLevelError;

    fn from_str(string: &str) -> Result<Level, Self::Err> {
        Ok(match string {
            "debug" => Level::Debug,
            "info" | "log" => Level::Info,
            "warning" => Level::Warning,
            "error" => Level::Error,
            "fatal" => Level::Fatal,
            _ => return Err(ParseLevelError),
        })
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Level::Debug => write!(f, "debug"),
            Level::Info => write!(f, "info"),
            Level::Warning => write!(f, "warning"),
            Level::Error => write!(f, "error"),
            Level::Fatal => write!(f, "fatal"),
        }
    }
}

impl Level {
    /// A quick way to check if the level is `debug`.
    pub fn is_debug(&self) -> bool {
        *self == Level::Debug
    }

    /// A quick way to check if the level is `info`.
    pub fn is_info(&self) -> bool {
        *self == Level::Info
    }

    /// A quick way to check if the level is `warning`.
    pub fn is_warning(&self) -> bool {
        *self == Level::Warning
    }

    /// A quick way to check if the level is `error`.
    pub fn is_error(&self) -> bool {
        *self == Level::Error
    }

    /// A quick way to check if the level is `fatal`.
    pub fn is_fatal(&self) -> bool {
        *self == Level::Fatal
    }
}

impl_str_serialization!(Level);

#[cfg(test)]
mod test_level {
    use super::*;
    use serde_json;

    #[test]
    fn test_log() {
        assert_eq!(Level::Info, serde_json::from_str("\"log\"").unwrap());
    }
}

/// A breadcrumb.
#[derive(Debug, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
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

    /// Severity level of the breadcrumb (required).
    #[serde(default)]
    pub level: Annotated<Level>,

    /// Human readable message for the breadcrumb.
    #[serde(default, skip_serializing_if = "annotated::is_none")]
    #[process_annotated_value(pii_kind = "freeform", cap = "message")]
    pub message: Annotated<Option<String>>,

    /// Custom user-defined data of this breadcrumb.
    #[serde(default, skip_serializing_if = "annotated::is_empty_map")]
    #[process_annotated_value(pii_kind = "databag")]
    pub data: Annotated<Map<Value>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
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
  "category": "mycategory",
  "level": "fatal",
  "message": "my message",
  "data": {
    "a": "b"
  },
  "c": "d"
}"#;

        let breadcrumb = Annotated::from(Breadcrumb {
            timestamp: serde_chrono::timestamp_to_datetime(42.0).into(),
            ty: "mytype".to_string().into(),
            category: Some("mycategory".to_string()).into(),
            level: Level::Fatal.into(),
            message: Some("my message".to_string()).into(),
            data: {
                let mut map = Map::new();
                map.insert(
                    "a".to_string(),
                    Annotated::from(Value::String("b".to_string())),
                );
                Annotated::from(map)
            },
            other: {
                let mut map = Map::new();
                map.insert(
                    "c".to_string(),
                    Annotated::from(Value::String("d".to_string())),
                );
                Annotated::from(map)
            },
        });

        assert_eq!(breadcrumb, serde_json::from_str(json).unwrap());
        assert_eq!(json, &serde_json::to_string_pretty(&breadcrumb).unwrap());
    }

    #[test]
    fn test_default_values() {
        let input = r#"{"timestamp":42}"#;
        let output = r#"{"timestamp":42,"type":"default","level":"info"}"#;

        let breadcrumb = Annotated::from(Breadcrumb {
            timestamp: serde_chrono::timestamp_to_datetime(42.0).into(),
            ty: default_breadcrumb_type(),
            category: None.into(),
            level: Level::default().into(),
            message: None.into(),
            data: Map::new().into(),
            other: Map::new().into(),
        });

        assert_eq!(breadcrumb, serde_json::from_str(input).unwrap());
        assert_eq!(output, &serde_json::to_string(&breadcrumb).unwrap());
    }
}

/// Represents a full event for Sentry.
#[derive(Debug, Default, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct Event {
    /// Unique identifier of this event.
    #[serde(
        default,
        rename = "event_id",
        skip_serializing_if = "annotated::is_none",
        serialize_with = "serialize_event_id"
    )]
    pub id: Annotated<Option<Uuid>>,

    /// Severity level of the event (defaults to "error").
    #[serde(default = "default_event_level")]
    pub level: Annotated<Level>,

    /// Manual fingerprint override.
    // Note this is a `Vec` and not `Array` intentionally
    #[serde(default = "fingerprint::default", deserialize_with = "fingerprint::deserialize")]
    pub fingerprint: Annotated<Vec<String>>,

    /// List of breadcrumbs recorded before this event.
    #[serde(default, skip_serializing_if = "annotated::is_empty_values")]
    #[process_annotated_value]
    pub breadcrumbs: Annotated<Values<Breadcrumb>>,
}

use utils::serde::CustomSerialize;

fn serialize_event_id<S: Serializer>(
    annotated: &Annotated<Option<Uuid>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    struct EventIdSerialize;

    impl CustomSerialize<Option<Uuid>> for EventIdSerialize {
        fn serialize<S>(value: &Option<Uuid>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match value {
                Some(uuid) => serializer.serialize_some(&uuid.simple().to_string()),
                None => serializer.serialize_none(),
            }
        }
    }

    annotated.serialize_with(serializer, EventIdSerialize)
}

fn default_event_level() -> Annotated<Level> {
    Level::Error.into()
}

mod fingerprint {
    use super::*;
    use utils::serde::CustomDeserialize;

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum Fingerprint {
        Bool(bool),
        Signed(i64),
        Unsigned(u64),
        Float(f64),
        String(String),
    }

    impl Into<Option<String>> for Fingerprint {
        fn into(self) -> Option<String> {
            match self {
                Fingerprint::Bool(b) => Some(if b { "True" } else { "False" }.to_string()),
                Fingerprint::Signed(s) => Some(s.to_string()),
                Fingerprint::Unsigned(u) => Some(u.to_string()),
                Fingerprint::Float(f) => if f.abs() < (1i64 << 53) as f64 {
                    Some(f.trunc().to_string())
                } else {
                    None
                },
                Fingerprint::String(s) => Some(s),
            }
        }
    }

    struct FingerprintDeserialize;

    impl<'de> CustomDeserialize<'de, Vec<String>> for FingerprintDeserialize {
        fn deserialize<D>(deserializer: D) -> Result<Vec<String>, D::Error>
        where
            D: Deserializer<'de>,
        {
            // TODO: Normalize to default fingerprint. The old solution used to deserialize into a
            // buffer to rule out syntax errors and then unwrapped to DEFAULT_FINGERPRINT.
            Ok(Vec::<Fingerprint>::deserialize(deserializer)?
                .into_iter()
                .filter_map(Fingerprint::into)
                .collect())
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Annotated<Vec<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Annotated::deserialize_with(deserializer, FingerprintDeserialize)
    }

    pub fn default() -> Annotated<Vec<String>> {
        vec!["{{ default }}".to_string()].into()
    }
}

#[derive(Debug, Deserialize)]
struct EventMetaDeserializeHelper {
    metadata: Option<MetaMap>,
}

/// Deserializes an annotated event with meta data from the given deserializer.
pub fn deserialize_event<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Annotated<Event>, D::Error> {
    deserialize_with_meta(deserializer)
}

/// Deserializes an annotated object with embedded meta data from the given deserializer.
pub(crate) fn deserialize_with_meta<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Annotated<T>, D::Error> {
    let content = Content::deserialize(deserializer)?;
    let helper = EventMetaDeserializeHelper::deserialize(ContentRefDeserializer::new(&content))?;
    let meta_map = helper.metadata.unwrap_or_default();
    meta::deserialize_meta(ContentDeserializer::new(content), meta_map)
}

/// Deserializes an annotated object with embedded meta data from the given deserializer.
pub(crate) fn from_str<'de, T: Deserialize<'de>>(
    s: &'de str,
) -> Result<Annotated<T>, serde_json::Error> {
    deserialize_with_meta(&mut serde_json::Deserializer::from_str(s))
}

#[derive(Debug, Serialize)]
struct EventMetaSerializeHelper<'a, T: Serialize + 'a> {
    #[serde(flatten)]
    event: Option<&'a T>,
    metadata: MetaTree,
}

/// Serializes a annotated value and its meta data into the given serializer.
pub(crate) fn serialize_with_meta<S: Serializer, T: Serialize>(
    annotated: &Annotated<T>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::Error;
    EventMetaSerializeHelper {
        event: annotated.value(),
        metadata: meta::serialize_meta(annotated).map_err(S::Error::custom)?,
    }.serialize(serializer)
}

/// Like `serialize_with_meta` but produces a JSON string.
pub(crate) fn to_string<T: Serialize>(
    annotated: &Annotated<T>,
) -> Result<String, serde_json::Error> {
    let mut ser = serde_json::Serializer::new(Vec::with_capacity(128));
    serialize_with_meta(annotated, &mut ser)?;
    Ok(unsafe { String::from_utf8_unchecked(ser.into_inner()) })
}

/// Serializes an event and its meta data into the given serializer.
pub fn serialize_event<S: Serializer>(
    event: &Annotated<Event>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_with_meta(event, serializer)
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
  "event_id": "52df9022835246eeb317dbd739ccd059",
  "level": "debug",
  "fingerprint": [
    "myprint"
  ],
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
            level: Level::Debug.into(),
            fingerprint: Annotated::from(vec!["myprint".to_string()]),
            breadcrumbs: Default::default(),
        });

        assert_eq!(event, deserialize(json).unwrap());
        assert_eq!(json, serialize(&event).unwrap());
    }

    #[test]
    fn test_default_values() {
        let input = r#"{"event_id":"52df9022-8352-46ee-b317-dbd739ccd059"}"#;
        let output = r#"{
  "event_id": "52df9022835246eeb317dbd739ccd059",
  "level": "error",
  "fingerprint": [
    "{{ default }}"
  ]
}"#;
        let event = Annotated::from(Event {
            id: Some("52df9022-8352-46ee-b317-dbd739ccd059".parse().unwrap()).into(),
            level: Level::Error.into(),
            fingerprint: fingerprint::default(),
            breadcrumbs: Default::default(),
        });

        assert_eq!(event, serde_json::from_str(input).unwrap());
        assert_eq!(output, &serde_json::to_string_pretty(&event).unwrap());
    }
}
