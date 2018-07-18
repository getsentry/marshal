//! Types of the sentry protocol.

use std::{fmt, str};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serializer};
use uuid::Uuid;

use super::buffer::{Content, ContentDeserializer};
use super::common::{Map, Value, Values};
use super::meta::Annotated;
use super::serde::CustomSerialize;
use super::{serde_chrono, utils};

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
    fn default() -> Self {
        Level::Info
    }
}

impl str::FromStr for Level {
    type Err = ParseLevelError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
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

impl_str_serde!(Level);

#[cfg(test)]
mod test_level {
    use protocol::*;
    use serde_json;

    #[test]
    fn test_log() {
        assert_eq_dbg!(Level::Info, serde_json::from_str("\"log\"").unwrap());
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
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub category: Annotated<Option<String>>,

    /// Severity level of the breadcrumb (required).
    #[serde(default)]
    pub level: Annotated<Level>,

    /// Human readable message for the breadcrumb.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "freeform", cap = "message")]
    pub message: Annotated<Option<String>>,

    /// Custom user-defined data of this breadcrumb.
    #[serde(default, skip_serializing_if = "utils::is_empty_map")]
    #[process_annotated_value(pii_kind = "databag")]
    pub data: Annotated<Map<Value>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

#[cfg(test)]
mod test_breadcrumb {
    use chrono::{TimeZone, Utc};
    use protocol::*;
    use serde_json;

    #[test]
    fn test_roundtrip() {
        let json = r#"{
  "timestamp": 946684800,
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
            timestamp: Utc.ymd(2000, 1, 1).and_hms(0, 0, 0).into(),
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

        assert_eq_dbg!(breadcrumb, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, &serde_json::to_string_pretty(&breadcrumb).unwrap());
    }

    #[test]
    fn test_default_values() {
        let input = r#"{"timestamp":946684800}"#;
        let output = r#"{"timestamp":946684800,"type":"default","level":"info"}"#;

        let breadcrumb = Annotated::from(Breadcrumb {
            timestamp: Utc.ymd(2000, 1, 1).and_hms(0, 0, 0).into(),
            ty: "default".to_string().into(),
            category: None.into(),
            level: Level::default().into(),
            message: None.into(),
            data: Map::new().into(),
            other: Map::new().into(),
        });

        assert_eq_dbg!(breadcrumb, serde_json::from_str(input).unwrap());
        assert_eq_str!(output, serde_json::to_string(&breadcrumb).unwrap());
    }
}

mod fingerprint {
    use super::super::buffer::ContentDeserializer;
    use super::super::serde::CustomDeserialize;
    use super::*;

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
            use serde::de::Error;
            let content = ContentDeserializer::<D::Error>::new(Content::deserialize(deserializer)?);
            match Vec::<Fingerprint>::deserialize(content) {
                Ok(vec) => Ok(vec.into_iter().filter_map(Fingerprint::into).collect()),
                Err(_) => Err(D::Error::custom("invalid fingerprint value")),
            }
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Annotated<Vec<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Annotated::deserialize_with(deserializer, FingerprintDeserialize).map(
            |Annotated(value, meta)| {
                let value = value.unwrap_or_else(|| vec!["{{ default }}".to_string()]);
                Annotated::new(value, meta)
            },
        )
    }

    pub fn default() -> Annotated<Vec<String>> {
        vec!["{{ default }}".to_string()].into()
    }
}

#[cfg(test)]
mod test_fingerprint {
    use super::fingerprint;
    use protocol::*;
    use serde_json;

    fn deserialize(json: &str) -> Result<Annotated<Vec<String>>, serde_json::Error> {
        fingerprint::deserialize(&mut serde_json::Deserializer::from_str(json))
    }

    #[test]
    fn test_fingerprint_string() {
        assert_eq_dbg!(
            Annotated::from(vec!["fingerprint".to_string()]),
            deserialize("[\"fingerprint\"]").unwrap()
        );
    }

    #[test]
    fn test_fingerprint_bool() {
        assert_eq_dbg!(
            Annotated::from(vec!["True".to_string(), "False".to_string()]),
            deserialize("[true, false]").unwrap()
        );
    }

    #[test]
    fn test_fingerprint_number() {
        assert_eq_dbg!(
            Annotated::from(vec!["-22".to_string()]),
            deserialize("[-22]").unwrap()
        );
    }

    #[test]
    fn test_fingerprint_float() {
        assert_eq_dbg!(
            Annotated::from(vec!["3".to_string()]),
            deserialize("[3.0]").unwrap()
        );
    }

    #[test]
    fn test_fingerprint_float_trunc() {
        assert_eq_dbg!(
            Annotated::from(vec!["3".to_string()]),
            deserialize("[3.5]").unwrap()
        );
    }

    #[test]
    fn test_fingerprint_float_strip() {
        assert_eq_dbg!(Annotated::from(vec![]), deserialize("[-1e100]").unwrap());
    }

    #[test]
    fn test_fingerprint_float_bounds() {
        assert_eq_dbg!(
            Annotated::from(vec![]),
            deserialize("[1.7976931348623157e+308]").unwrap()
        );
    }

    #[test]
    fn test_fingerprint_invalid_fallback() {
        assert_eq_dbg!(
            Annotated::new(
                vec!["{{ default }}".to_string()],
                Meta::from_error("invalid fingerprint value")
            ),
            deserialize("[\"a\", null, \"d\"]").unwrap()
        );
    }

    #[test]
    fn test_fingerprint_empty() {
        assert_eq_dbg!(Annotated::from(vec![]), deserialize("[]").unwrap());
    }
}

mod event {
    use super::*;
    use std::collections::BTreeMap;

    pub fn serialize_id<S: Serializer>(
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

    pub fn default_level() -> Annotated<Level> {
        Level::Error.into()
    }

    pub fn default_platform() -> Annotated<String> {
        "other".to_string().into()
    }

    impl<'de> Deserialize<'de> for Event {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let mut id = None;
            let mut level = None;
            let mut fingerprint = None;
            let mut culprit = None;
            let mut transaction = None;
            let mut message = None;
            // let mut logentry = None;
            let mut logger = None;
            let mut modules = None;
            let mut platform = None;
            let mut timestamp = None;
            let mut server_name = None;
            let mut release = None;
            let mut dist = None;
            // let mut repos = None;
            let mut environment = None;
            // let mut user = None;
            // let mut request = None;
            // let mut contexts = None;
            let mut breadcrumbs = None;
            // let mut exceptions = None;
            // let mut stacktrace = None;
            // let mut template = None;
            // let mut threads = None;
            let mut tags = None;
            let mut extra = None;
            // let mut debug_meta = None;
            // let mut sdk_info = None;
            let mut other: Map<Value> = Default::default();

            for (key, content) in BTreeMap::<String, Content>::deserialize(deserializer)? {
                let deserializer = ContentDeserializer::new(content);
                match key.as_str() {
                    "" => (),
                    "event_id" => id = Some(Deserialize::deserialize(deserializer)?),
                    "level" => level = Some(Deserialize::deserialize(deserializer)?),
                    "fingerprint" => fingerprint = Some(fingerprint::deserialize(deserializer)?),
                    "culprit" => culprit = Some(Deserialize::deserialize(deserializer)?),
                    "transaction" => transaction = Some(Deserialize::deserialize(deserializer)?),
                    "message" => message = Some(Deserialize::deserialize(deserializer)?),
                    // "logentry" => logentry = Some(Deserialize::deserialize(deserializer)?),
                    // "sentry.interfaces.Message" => if logentry.is_none() {
                    //     logentry = Some(Deserialize::deserialize(deserializer)?)
                    // },
                    "logger" => logger = Some(Deserialize::deserialize(deserializer)?),
                    "modules" => modules = Some(Deserialize::deserialize(deserializer)?),
                    "platform" => platform = Some(Deserialize::deserialize(deserializer)?),
                    "timestamp" => timestamp = Some(serde_chrono::deserialize(deserializer)?),
                    "server_name" => server_name = Some(Deserialize::deserialize(deserializer)?),
                    "release" => release = Some(Deserialize::deserialize(deserializer)?),
                    "dist" => dist = Some(Deserialize::deserialize(deserializer)?),
                    // "repos" => repos = Some(Deserialize::deserialize(deserializer)?),
                    "environment" => environment = Some(Deserialize::deserialize(deserializer)?),
                    // "user" => user = Some(Deserialize::deserialize(deserializer)?),
                    // "sentry.interfaces.User" => if user.is_none() {
                    //     user = Some(Deserialize::deserialize(deserializer)?);
                    // },
                    // "request" => request = Some(Deserialize::deserialize(deserializer)?),
                    // "sentry.interfaces.Http" => if request.is_none() {
                    //     request = Some(Deserialize::deserialize(deserializer)?);
                    // },
                    // "contexts" => contexts = Some(Deserialize::deserialize(deserializer)?),
                    // "sentry.interfaces.Contexts" => if contexts.is_none() {
                    //     contexts = Some(Deserialize::deserialize(deserializer)?);
                    // },
                    "breadcrumbs" => breadcrumbs = Some(Deserialize::deserialize(deserializer)?),
                    "sentry.interfaces.Breadcrumbs" => if breadcrumbs.is_none() {
                        breadcrumbs = Some(Deserialize::deserialize(deserializer)?);
                    },
                    // "exception" => exceptions = Some(Deserialize::deserialize(deserializer)?),
                    // "sentry.interfaces.Exception" => if exceptions.is_none() {
                    //     exceptions = Some(Deserialize::deserialize(deserializer)?)
                    // },
                    // "stacktrace" => stacktrace = Some(Deserialize::deserialize(deserializer)?),
                    // "sentry.interfaces.Stacktrace" => if stacktrace.is_none() {
                    //     stacktrace = Some(Deserialize::deserialize(deserializer)?)
                    // },
                    // "template" => template = Some(Deserialize::deserialize(deserializer)?),
                    // "sentry.interfaces.Template" => if template.is_none() {
                    //     template = Some(Deserialize::deserialize(deserializer)?)
                    // },
                    // "threads" => threads = Some(Deserialize::deserialize(deserializer)?),
                    // "sentry.interfaces.Threads" => if threads.is_none() {
                    //     threads = Some(Deserialize::deserialize(deserializer)?)
                    // },
                    "tags" => tags = Some(Deserialize::deserialize(deserializer)?),
                    "extra" => extra = Some(Deserialize::deserialize(deserializer)?),
                    // "debug_meta" => debug_meta = Some(Deserialize::deserialize(deserializer)?),
                    // "sentry.interfaces.DebugMeta" => if debug_meta.is_none() {
                    //     debug_meta = Some(Deserialize::deserialize(deserializer)?)
                    // },
                    // "sdk" => sdk_info = Some(Deserialize::deserialize(deserializer)?),
                    _ => {
                        other.insert(key, Deserialize::deserialize(deserializer)?);
                    }
                }
            }

            Ok(Event {
                id: id.unwrap_or_default(),
                level: level.unwrap_or_else(|| default_level()),
                fingerprint: fingerprint.unwrap_or_else(|| fingerprint::default()),
                culprit: culprit.unwrap_or_default(),
                transaction: transaction.unwrap_or_default(),
                message: message.unwrap_or_default(),
                logger: logger.unwrap_or_default(),
                modules: modules.unwrap_or_default(),
                platform: platform.unwrap_or_else(|| default_platform()),
                timestamp: timestamp.unwrap_or_default(),
                server_name: server_name.unwrap_or_default(),
                release: release.unwrap_or_default(),
                dist: dist.unwrap_or_default(),
                environment: environment.unwrap_or_default(),
                breadcrumbs: breadcrumbs.unwrap_or_default(),
                tags: tags.unwrap_or_default(),
                extra: extra.unwrap_or_default(),
                other: Annotated::from(other),
            })
        }
    }
}

/// Represents a full event for Sentry.
#[derive(Debug, Default, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct Event {
    /// Unique identifier of this event.
    #[serde(
        rename = "event_id",
        skip_serializing_if = "utils::is_none",
        serialize_with = "event::serialize_id"
    )]
    pub id: Annotated<Option<Uuid>>,

    /// Severity level of the event (defaults to "error").
    pub level: Annotated<Level>,

    /// Manual fingerprint override.
    // XXX: This is a `Vec` and not `Array` intentionally
    pub fingerprint: Annotated<Vec<String>>,

    /// Custom culprit of the event.
    #[serde(skip_serializing_if = "utils::is_none")]
    pub culprit: Annotated<Option<String>>,

    /// Transaction name of the event.
    #[serde(skip_serializing_if = "utils::is_none")]
    pub transaction: Annotated<Option<String>>,

    /// Custom message for this event.
    // TODO: Consider to normalize this right away into logentry
    #[serde(skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "freeform", cap = "message")]
    pub message: Annotated<Option<String>>,

    // TODO: logentry
    /// Logger that created the event.
    #[serde(skip_serializing_if = "utils::is_none")]
    pub logger: Annotated<Option<String>>,

    /// Name and versions of installed modules.
    #[serde(skip_serializing_if = "utils::is_empty_map")]
    #[process_annotated_value(pii_kind = "databag")]
    pub modules: Annotated<Map<String>>,

    /// Platform identifier of this event (defaults to "other").
    pub platform: Annotated<String>,

    /// Timestamp when the event was created.
    #[serde(with = "serde_chrono", skip_serializing_if = "utils::is_none")]
    pub timestamp: Annotated<Option<DateTime<Utc>>>,

    /// Server or device name the event was generated on.
    #[serde(skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "hostname")]
    pub server_name: Annotated<Option<String>>,

    /// Program's release identifier.
    #[serde(skip_serializing_if = "utils::is_none")]
    pub release: Annotated<Option<String>>,

    /// Program's distribution identifier.
    #[serde(skip_serializing_if = "utils::is_none")]
    pub dist: Annotated<Option<String>>,

    // TODO: repos
    /// Environment the environment was generated in ("production" or "development").
    #[serde(skip_serializing_if = "utils::is_none")]
    pub environment: Annotated<Option<String>>,

    // TODO: user
    // TODO: request
    // TODO: contexts
    /// List of breadcrumbs recorded before this event.
    #[serde(skip_serializing_if = "utils::is_empty_values")]
    #[process_annotated_value]
    pub breadcrumbs: Annotated<Values<Breadcrumb>>,

    // TODO: exceptions (rename = "exception")
    // TODO: stacktrace
    // TODO: template_info (rename = "template")
    // TODO: threads
    /// Custom tags for this event.
    #[serde(skip_serializing_if = "utils::is_empty_map")]
    #[process_annotated_value(pii_kind = "databag")]
    pub tags: Annotated<Map<String>>,

    /// Arbitrary extra information set by the user.
    #[serde(skip_serializing_if = "utils::is_empty_map")]
    #[process_annotated_value(pii_kind = "databag")]
    pub extra: Annotated<Map<Value>>,

    // TODO: debug_meta
    // TODO: sdk_info (rename = "sdk")
    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

#[cfg(test)]
mod test_event {
    use chrono::{TimeZone, Utc};
    use protocol::*;
    use serde_json;

    fn serialize(event: &Annotated<Event>) -> Result<String, serde_json::Error> {
        let mut serializer = serde_json::Serializer::pretty(Vec::new());
        event.serialize_with_meta(&mut serializer)?;
        Ok(String::from_utf8(serializer.into_inner()).unwrap())
    }

    fn deserialize(string: &str) -> Result<Annotated<Event>, serde_json::Error> {
        Annotated::<Event>::from_json(string)
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
  "culprit": "myculprit",
  "transaction": "mytransaction",
  "message": "mymessage",
  "logger": "mylogger",
  "modules": {
    "mymodule": "1.0.0"
  },
  "platform": "myplatform",
  "timestamp": 946684800,
  "server_name": "myhost",
  "release": "myrelease",
  "dist": "mydist",
  "environment": "myenv",
  "tags": {
    "tag": "value"
  },
  "extra": {
    "extra": "value"
  },
  "other": "value",
  "": {
    "event_id": {
      "": {
        "err": [
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
            culprit: Some("myculprit".to_string()).into(),
            transaction: Some("mytransaction".to_string()).into(),
            message: Some("mymessage".to_string()).into(),
            logger: Some("mylogger".to_string()).into(),
            modules: {
                let mut map = Map::new();
                map.insert("mymodule".to_string(), "1.0.0".to_string().into());
                Annotated::from(map)
            },
            platform: "myplatform".to_string().into(),
            timestamp: Some(Utc.ymd(2000, 1, 1).and_hms(0, 0, 0)).into(),
            server_name: Some("myhost".to_string()).into(),
            release: Some("myrelease".to_string()).into(),
            dist: Some("mydist".to_string()).into(),
            environment: Some("myenv".to_string()).into(),
            breadcrumbs: Default::default(),
            tags: {
                let mut map = Map::new();
                map.insert("tag".to_string(), "value".to_string().into());
                Annotated::from(map)
            },
            extra: {
                let mut map = Map::new();
                map.insert(
                    "extra".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        });

        assert_eq_dbg!(event, deserialize(json).unwrap());
        assert_eq_str!(json, serialize(&event).unwrap());
    }

    #[test]
    fn test_default_values() {
        let input = r#"{"event_id":"52df9022-8352-46ee-b317-dbd739ccd059"}"#;
        let output = r#"{
  "event_id": "52df9022835246eeb317dbd739ccd059",
  "level": "error",
  "fingerprint": [
    "{{ default }}"
  ],
  "platform": "other"
}"#;
        let event = Annotated::from(Event {
            id: Some("52df9022-8352-46ee-b317-dbd739ccd059".parse().unwrap()).into(),
            level: Level::Error.into(),
            fingerprint: vec!["{{ default }}".to_string()].into(),
            culprit: None.into(),
            transaction: None.into(),
            message: None.into(),
            logger: None.into(),
            modules: Default::default(),
            platform: "other".to_string().into(),
            timestamp: None.into(),
            server_name: None.into(),
            release: None.into(),
            dist: None.into(),
            environment: None.into(),
            breadcrumbs: Default::default(),
            tags: Default::default(),
            extra: Default::default(),
            other: Default::default(),
        });

        assert_eq_dbg!(event, serde_json::from_str(input).unwrap());
        assert_eq_str!(output, serde_json::to_string_pretty(&event).unwrap());
    }
}
