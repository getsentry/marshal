//! Types of the sentry protocol.

use std::{fmt, str};

use chrono::{DateTime, Utc};
use debugid::DebugId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use super::buffer::{Content, ContentDeserializer};
use super::common::{Array, Map, Value, Values};
use super::meta::Annotated;
use super::serde::CustomSerialize;
use super::{serde_chrono, utils};

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

mod level {
    use super::*;
    use serde::de;

    struct LevelVisitor;

    impl<'de> de::Visitor<'de> for LevelVisitor {
        type Value = Level;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a severity level")
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            // Log level from: https://docs.python.org/2/library/logging.html#logging-levels
            Ok(match v {
                10 => Level::Debug,
                20 => Level::Info,
                30 => Level::Warning,
                40 => Level::Error,
                50 => Level::Fatal,
                _ => return Err(E::custom(ParseLevelError)),
            })
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.parse().map_err(E::custom)
        }
    }

    impl<'de> Deserialize<'de> for Level {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_any(LevelVisitor)
        }
    }

    impl_str_ser!(Level);
}

#[cfg(test)]
mod test_level {
    use protocol::*;
    use serde_json;

    #[test]
    fn test_log() {
        assert_eq_dbg!(Level::Info, serde_json::from_str("\"log\"").unwrap());
    }

    #[test]
    fn test_numeric() {
        assert_eq_dbg!(Level::Warning, serde_json::from_str("30").unwrap());
    }
}

/// A log entry message.
///
/// A log message is similar to the `message` attribute on the event itself but
/// can additionally hold optional parameters.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct LogEntry {
    /// The log message with parameter placeholders (required).
    #[process_annotated_value(pii_kind = "freeform", cap = "message")]
    pub message: Annotated<String>,

    /// Positional parameters to be interpolated into the log message.
    #[serde(default, skip_serializing_if = "utils::is_empty_array")]
    #[process_annotated_value(pii_kind = "databag")]
    pub params: Annotated<Array<Value>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

#[cfg(test)]
mod test_logentry {
    use protocol::*;
    use serde_json;

    #[test]
    fn test_roundtrip() {
        let json = r#"{
  "message": "Hello, %s %s!",
  "params": [
    "World",
    1
  ],
  "other": "value"
}"#;

        let entry = LogEntry {
            message: "Hello, %s %s!".to_string().into(),
            params: vec![
                Value::String("World".to_string()).into(),
                Value::U64(1).into(),
            ].into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        };

        assert_eq_dbg!(entry, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&entry).unwrap());
    }

    #[test]
    fn test_default_values() {
        let json = r#"{"message":"mymessage"}"#;
        let entry = LogEntry {
            message: "mymessage".to_string().into(),
            params: Default::default(),
            other: Default::default(),
        };

        assert_eq_dbg!(entry, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&entry).unwrap());
    }

    #[test]
    fn test_invalid() {
        let entry: Annotated<LogEntry> = Annotated::from_error("missing field `message`");
        assert_eq_dbg!(entry, serde_json::from_str("{}").unwrap());
    }
}

/// Reference to a source code repository.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct RepoReference {
    /// Name of the repository as registered in Sentry (required).
    pub name: Annotated<String>,

    /// Prefix to apply to source code when pairing it with files in the repository.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub prefix: Annotated<Option<String>>,

    /// Current reivision of the repository at build time.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub revision: Annotated<Option<String>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    pub other: Annotated<Map<Value>>,
}

#[cfg(test)]
mod test_repos {
    use super::*;
    use serde_json;

    #[test]
    fn test_roundtrip() {
        let json = r#"{
  "name": "marshal",
  "prefix": "./marshal",
  "revision": "e879d26974bbbb7f047105182f04fbfd4732c4e5",
  "other": "value"
}"#;

        let repo = RepoReference {
            name: "marshal".to_string().into(),
            prefix: Some("./marshal".to_string()).into(),
            revision: Some("e879d26974bbbb7f047105182f04fbfd4732c4e5".to_string()).into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        };

        assert_eq_dbg!(repo, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&repo).unwrap());
    }

    #[test]
    fn test_default_values() {
        let json = r#"{"name":"marshal"}"#;
        let repo = RepoReference {
            name: "marshal".to_string().into(),
            prefix: None.into(),
            revision: None.into(),
            other: Default::default(),
        };

        assert_eq_dbg!(repo, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&repo).unwrap());
    }

    #[test]
    fn test_invalid() {
        let repo: Annotated<RepoReference> = Annotated::from_error("missing field `name`");
        assert_eq_dbg!(repo, serde_json::from_str("{}").unwrap());
    }
}

/// Information about the user who triggered an event.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct User {
    /// Unique identifier of the user.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "id")]
    pub id: Annotated<Option<String>>,

    /// Email address of the user.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "email")]
    pub email: Annotated<Option<String>>,

    /// Remote IP address of the user. Defaults to "{{auto}}".
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "ip")]
    pub ip_address: Annotated<Option<String>>,

    /// Human readable name of the user.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "username")]
    pub username: Annotated<Option<String>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

#[cfg(test)]
mod test_user {
    use super::*;
    use serde_json;

    #[test]
    fn test_roundtrip() {
        let json = r#"{
  "id": "e4e24881-8238-4539-a32b-d3c3ecd40568",
  "email": "mail@example.org",
  "ip_address": "{{auto}}",
  "username": "John Doe",
  "other": "value"
}"#;
        let user = User {
            id: Some("e4e24881-8238-4539-a32b-d3c3ecd40568".to_string()).into(),
            email: Some("mail@example.org".to_string()).into(),
            ip_address: Some("{{auto}}".to_string()).into(),
            username: Some("John Doe".to_string()).into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        };

        assert_eq_dbg!(user, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&user).unwrap());
    }

    #[test]
    fn test_default_values() {
        let json = "{}";
        let user = User {
            id: None.into(),
            email: None.into(),
            ip_address: None.into(),
            username: None.into(),
            other: Default::default(),
        };

        assert_eq_dbg!(user, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&user).unwrap());
    }
}

/// Wrapper type for query-string like maps.
#[derive(Debug, Clone, Default, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct Query(pub Map<Value>);

/// Wrapper type for request header maps.
#[derive(Debug, Clone, Default, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct Cookies(pub Map<String>);

/// Wrapper type for request header maps.
#[derive(Debug, Clone, Default, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct Headers(pub Map<String>);

/// Http request information.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct Request {
    /// URL of the request.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    // TODO: cap?
    pub url: Annotated<Option<String>>,

    /// HTTP request method.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub method: Annotated<Option<String>>,

    /// Request data in any format that makes sense.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "databag")]
    // TODO: cap?
    // TODO: Custom logic + info
    pub data: Annotated<Option<Value>>,

    /// URL encoded HTTP query string.
    #[serde(default, skip_serializing_if = "request::is_empty_query")]
    #[process_annotated_value(pii_kind = "databag")]
    pub query_string: Annotated<Query>,

    /// URL encoded contents of the Cookie header.
    #[serde(default, skip_serializing_if = "request::is_empty_cookies")]
    #[process_annotated_value(pii_kind = "databag")]
    pub cookies: Annotated<Cookies>,

    /// HTTP request headers.
    #[serde(default, skip_serializing_if = "request::is_empty_headers")]
    #[process_annotated_value(pii_kind = "databag")]
    pub headers: Annotated<Headers>,

    /// Server environment data, such as CGI/WSGI.
    #[serde(default, skip_serializing_if = "utils::is_empty_map")]
    #[process_annotated_value(pii_kind = "databag")]
    // TODO: cap?
    pub env: Annotated<Map<Value>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

mod request {
    use cookie::Cookie;
    use queryst;
    use serde::de;
    use serde_json;

    use super::super::utils;
    use super::*;

    pub fn is_empty_query(annotated: &Annotated<Query>) -> bool {
        utils::skip_if(annotated, |query| query.0.is_empty())
    }

    pub fn is_empty_cookies(annotated: &Annotated<Cookies>) -> bool {
        utils::skip_if(annotated, |cookies| cookies.0.is_empty())
    }

    pub fn is_empty_headers(annotated: &Annotated<Headers>) -> bool {
        utils::skip_if(annotated, |headers| headers.0.is_empty())
    }

    struct ParseQueryError(String);

    impl fmt::Display for ParseQueryError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl From<queryst::ParseError> for ParseQueryError {
        fn from(error: queryst::ParseError) -> Self {
            ParseQueryError(error.message)
        }
    }

    impl From<serde_json::Error> for ParseQueryError {
        fn from(error: serde_json::Error) -> Self {
            ParseQueryError(error.to_string())
        }
    }

    fn parse_qs(qs: &str) -> Result<Query, ParseQueryError> {
        let value = queryst::parse(qs)?;
        Ok(serde_json::from_value(value)?)
    }

    struct QueryVisitor;

    impl<'de> de::Visitor<'de> for QueryVisitor {
        type Value = Query;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a query string or map")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            let qs = if v.starts_with('?') { &v[1..] } else { v };
            parse_qs(qs).map_err(E::custom)
        }

        fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut query = Map::new();
            while let Some(entry) = map.next_entry()? {
                query.insert(entry.0, entry.1);
            }
            Ok(Query(query))
        }
    }

    impl<'de> Deserialize<'de> for Query {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_any(QueryVisitor)
        }
    }

    struct CookiesVisitor;

    impl<'de> de::Visitor<'de> for CookiesVisitor {
        type Value = Cookies;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a cookie map or header string")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            let mut cookies = Map::new();
            for cookie in v.split("; ") {
                let cookie = Cookie::parse_encoded(cookie).map_err(E::custom)?;
                cookies.insert(cookie.name().to_string(), cookie.value().to_string().into());
            }
            Ok(Cookies(cookies))
        }

        fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut cookies = Map::new();
            while let Some(entry) = map.next_entry()? {
                cookies.insert(entry.0, entry.1);
            }
            Ok(Cookies(cookies))
        }
    }

    impl<'de> Deserialize<'de> for Cookies {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_any(CookiesVisitor)
        }
    }

    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    fn capitalize_header(header: String) -> String {
        header
            .split('-')
            .enumerate()
            .fold(String::new(), |mut all, (i, part)| {
                // join
                if i > 0 {
                    all.push_str("-");
                }

                // capitalize the first characters
                let mut chars = part.chars();
                if let Some(c) = chars.next() {
                    all.extend(c.to_uppercase());
                }

                // copy all others
                all.extend(chars);
                all
            })
    }

    struct HeadersVisitor;

    impl<'de> de::Visitor<'de> for HeadersVisitor {
        type Value = Headers;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a headers map")
        }

        fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut headers = Map::new();
            while let Some(entry) = map.next_entry()? {
                headers.insert(capitalize_header(entry.0), entry.1);
            }
            Ok(Headers(headers))
        }
    }

    impl<'de> Deserialize<'de> for Headers {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_map(HeadersVisitor)
        }
    }
}

#[cfg(test)]
mod test_request {
    use super::*;
    use serde_json;

    #[test]
    fn test_roundtrip() {
        let json = r#"{
  "url": "https://google.com/search",
  "method": "GET",
  "data": {
    "some": 1
  },
  "query_string": {
    "q": "foo"
  },
  "cookies": {
    "GOOGLE": "1"
  },
  "headers": {
    "Referer": "https://google.com/"
  },
  "env": {
    "REMOTE_ADDR": "213.47.147.207"
  },
  "other": "value"
}"#;

        let request = Request {
            url: Some("https://google.com/search".to_string()).into(),
            method: Some("GET".to_string()).into(),
            data: {
                let mut map = Map::new();
                map.insert("some".to_string(), Value::U64(1).into());
                Annotated::from(Some(Value::Map(map)))
            },
            query_string: Query({
                let mut map = Map::new();
                map.insert("q".to_string(), Value::String("foo".to_string()).into());
                map
            }).into(),
            cookies: Cookies({
                let mut map = Map::new();
                map.insert("GOOGLE".to_string(), "1".to_string().into());
                map
            }).into(),
            headers: {
                let mut map = Map::new();
                map.insert(
                    "Referer".to_string(),
                    "https://google.com/".to_string().into(),
                );
                Annotated::from(Headers(map))
            },
            env: {
                let mut map = Map::new();
                map.insert(
                    "REMOTE_ADDR".to_string(),
                    Value::String("213.47.147.207".to_string()).into(),
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
        };

        assert_eq_dbg!(request, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&request).unwrap());
    }

    #[test]
    fn test_default_values() {
        let json = "{}";
        let request = Request {
            url: None.into(),
            method: None.into(),
            data: None.into(),
            query_string: Default::default(),
            cookies: Default::default(),
            headers: Default::default(),
            env: Default::default(),
            other: Default::default(),
        };

        assert_eq_dbg!(request, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&request).unwrap());
    }

    #[test]
    fn test_query_string() {
        let mut map = Map::new();
        map.insert("foo".to_string(), Value::String("bar".to_string()).into());
        let query = Annotated::from(Query(map));
        assert_eq_dbg!(query, serde_json::from_str("\"foo=bar\"").unwrap());
    }

    #[test]
    fn test_query_string_questionmark() {
        let mut map = Map::new();
        map.insert("foo".to_string(), Value::String("bar".to_string()).into());
        let query = Annotated::from(Query(map));
        assert_eq_dbg!(query, serde_json::from_str("\"?foo=bar\"").unwrap());
    }

    #[test]
    fn test_query_object() {
        let mut map = Map::new();
        map.insert("foo".to_string(), Value::String("bar".to_string()).into());
        let query = Annotated::from(Query(map));
        assert_eq_dbg!(query, serde_json::from_str(r#"{"foo":"bar"}"#).unwrap());
    }

    #[test]
    fn test_query_invalid() {
        let query = Annotated::<Query>::from_error(
            "invalid type: integer `42`, expected a query string or map",
        );
        assert_eq_dbg!(query, serde_json::from_str("42").unwrap());
    }

    #[test]
    fn test_cookies_string() {
        let json = "\" PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1;\"";

        let mut map = Map::new();
        map.insert(
            "PHPSESSID".to_string(),
            "298zf09hf012fh2".to_string().into(),
        );
        map.insert("csrftoken".to_string(), "u32t4o3tb3gg43".to_string().into());
        map.insert("_gat".to_string(), "1".to_string().into());

        let cookies = Annotated::from(Cookies(map));
        assert_eq_dbg!(cookies, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_cookies_object() {
        let json = r#"{"foo":"bar", "invalid": 42}"#;

        let mut map = Map::new();
        map.insert("foo".to_string(), "bar".to_string().into());
        map.insert(
            "invalid".to_string(),
            Annotated::from_error("invalid type: integer `42`, expected a string"),
        );

        let cookies = Annotated::from(Cookies(map));
        assert_eq_dbg!(cookies, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_cookies_invalid() {
        let cookies = Annotated::<Cookies>::from_error(
            "invalid type: integer `42`, expected a cookie map or header string",
        );
        assert_eq_dbg!(cookies, serde_json::from_str("42").unwrap());
    }

    #[test]
    fn test_header_normalization() {
        let json = r#"{
  "accept": "application/json",
  "x-sentry": "version=8",
  "-other-": "header"
}"#;

        let mut map = Map::new();
        map.insert("Accept".to_string(), "application/json".to_string().into());
        map.insert("X-Sentry".to_string(), "version=8".to_string().into());
        map.insert("-Other-".to_string(), "header".to_string().into());

        let query = Annotated::from(Headers(map));
        assert_eq_dbg!(query, serde_json::from_str(json).unwrap());
    }
}

/// Device information.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct DeviceContext {
    /// Name of the device.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(cap = "summary")]
    pub name: Annotated<Option<String>>,

    /// Family of the device model.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub family: Annotated<Option<String>>,

    /// Device model (human readable).
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub model: Annotated<Option<String>>,

    /// Device model (internal identifier).
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub model_id: Annotated<Option<String>>,

    /// Native cpu architecture of the device.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub arch: Annotated<Option<String>>,

    /// Current battery level (0-100).
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub battery_level: Annotated<Option<f32>>,

    /// Current screen orientation.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub orientation: Annotated<Option<String>>,

    /// Simulator/prod indicator.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub simulator: Annotated<Option<bool>>,

    /// Total memory available in bytes.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub memory_size: Annotated<Option<u64>>,

    /// How much memory is still available in bytes.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub free_memory: Annotated<Option<u64>>,

    /// How much memory is usable for the app in bytes.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub usable_memory: Annotated<Option<u64>>,

    /// Total storage size of the device in bytes.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub storage_size: Annotated<Option<u64>>,

    /// How much storage is free in bytes.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub free_storage: Annotated<Option<u64>>,

    /// Total size of the attached external storage in bytes (eg: android SDK card).
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub external_storage_size: Annotated<Option<u64>>,

    /// Free size of the attached external storage in bytes (eg: android SDK card).
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub external_free_storage: Annotated<Option<u64>>,

    /// Indicator when the device was booted.
    #[serde(default, with = "serde_chrono", skip_serializing_if = "utils::is_none")]
    pub boot_time: Annotated<Option<DateTime<Utc>>>,

    /// Timezone of the device.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub timezone: Annotated<Option<String>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

/// Operating system information.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct OsContext {
    /// Name of the operating system.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(cap = "summary")]
    pub name: Annotated<Option<String>>,

    /// Version of the operating system.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(cap = "summary")]
    pub version: Annotated<Option<String>>,

    /// Internal build number of the operating system.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(cap = "summary")]
    pub build: Annotated<Option<String>>,

    /// Current kernel version.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(cap = "summary")]
    pub kernel_version: Annotated<Option<String>>,

    /// Indicator if the OS is rooted (mobile mostly).
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub rooted: Annotated<Option<bool>>,

    /// Unprocessed operating system info.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(cap = "summary")]
    pub raw_description: Annotated<Option<String>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

/// Runtime information.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct RuntimeContext {
    /// Runtime name.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(cap = "summary")]
    pub name: Annotated<Option<String>>,

    /// Runtime version.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(cap = "summary")]
    pub version: Annotated<Option<String>>,

    /// Unprocessed runtime info.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(cap = "summary")]
    pub raw_description: Annotated<Option<String>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

/// Application information.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct AppContext {
    /// Start time of the app.
    #[serde(default, with = "serde_chrono", skip_serializing_if = "utils::is_none")]
    pub app_start_time: Annotated<Option<DateTime<Utc>>>,

    /// Device app hash (app specific device ID)
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "id", cap = "summary")]
    pub device_app_hash: Annotated<Option<String>>,

    /// Build identicator.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(cap = "summary")]
    pub build_type: Annotated<Option<String>>,

    /// App identifier (dotted bundle id).
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub app_identifier: Annotated<Option<String>>,

    /// Application name as it appears on the platform.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub app_name: Annotated<Option<String>>,

    /// Application version as it appears on the platform.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub app_version: Annotated<Option<String>>,

    /// Internal build ID as it appears on the platform.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(cap = "summary")]
    pub app_build: Annotated<Option<String>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

/// Web browser information.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct BrowserContext {
    /// Runtime name.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(cap = "summary")]
    pub name: Annotated<Option<String>>,

    /// Runtime version.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(cap = "summary")]
    pub version: Annotated<Option<String>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

/// Contexts describing the environment (e.g. device, os or browser).
#[derive(Debug, Clone, PartialEq)]
pub enum Context {
    /// Device information.
    Device(Box<DeviceContext>),
    /// Operating system information.
    Os(Box<OsContext>),
    /// Runtime information.
    Runtime(Box<RuntimeContext>),
    /// Application information.
    App(Box<AppContext>),
    /// Web browser information.
    Browser(Box<BrowserContext>),
    /// A context type that is unknown to this protocol specification.
    Other(String, Map<Value>),
}

mod context {
    use processor::{ProcessAnnotatedValue, Processor, ValueInfo};
    use std::rc::Rc;

    use super::super::buffer::{Content, ContentDeserializer};
    use super::super::tracked::Path;
    use super::*;

    impl<'de> Deserialize<'de> for Context {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            #[derive(Deserialize)]
            struct D<'a> {
                #[serde(default, rename = "type")]
                t: Option<String>,
                #[serde(flatten, borrow)]
                content: Content<'a>,
            };

            let key = deserializer.state().get::<Rc<Path>>().map(|p| p.key());
            let D { t, content } = D::deserialize(deserializer)?;
            let deserializer = ContentDeserializer::new(content);

            // The context type is either declared explicitly or inferred from the map key via
            // deserializer state. If the deserializer does not support state, we default to
            // "unknown".
            let ty = t.or(key).unwrap_or_else(|| "unknown".to_string());

            Ok(match ty.as_ref() {
                "device" => Context::Device(Deserialize::deserialize(deserializer)?),
                "os" => Context::Os(Deserialize::deserialize(deserializer)?),
                "runtime" => Context::Runtime(Deserialize::deserialize(deserializer)?),
                "app" => Context::App(Deserialize::deserialize(deserializer)?),
                "browser" => Context::Browser(Deserialize::deserialize(deserializer)?),
                _ => Context::Other(ty, Deserialize::deserialize(deserializer)?),
            })
        }
    }

    impl Serialize for Context {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            #[derive(Serialize)]
            struct S<'a, T: Serialize> {
                #[serde(rename = "type")]
                t: &'a str,
                #[serde(flatten)]
                context: T,
            }

            match self {
                Context::Device(ref device) => S {
                    t: "device",
                    context: device,
                }.serialize(serializer),
                Context::Os(ref os) => S {
                    t: "os",
                    context: os,
                }.serialize(serializer),
                Context::Runtime(ref runtime) => S {
                    t: "runtime",
                    context: runtime,
                }.serialize(serializer),
                Context::App(ref app) => S {
                    t: "app",
                    context: app,
                }.serialize(serializer),
                Context::Browser(ref browser) => S {
                    t: "browser",
                    context: browser,
                }.serialize(serializer),
                Context::Other(ref ty, ref other) => S {
                    t: ty,
                    context: other,
                }.serialize(serializer),
            }
        }
    }

    impl ProcessAnnotatedValue for Context {
        fn process_annotated_value(
            annotated: Annotated<Self>,
            processor: &Processor,
            info: &ValueInfo,
        ) -> Annotated<Self> {
            match annotated {
                Annotated(Some(Context::Device(context)), meta) => {
                    ProcessAnnotatedValue::process_annotated_value(
                        Annotated::new(context, meta),
                        processor,
                        info,
                    ).map(Context::Device)
                }
                Annotated(Some(Context::Os(context)), meta) => {
                    ProcessAnnotatedValue::process_annotated_value(
                        Annotated::new(context, meta),
                        processor,
                        info,
                    ).map(Context::Os)
                }
                Annotated(Some(Context::Runtime(context)), meta) => {
                    ProcessAnnotatedValue::process_annotated_value(
                        Annotated::new(context, meta),
                        processor,
                        info,
                    ).map(Context::Runtime)
                }
                Annotated(Some(Context::App(context)), meta) => {
                    ProcessAnnotatedValue::process_annotated_value(
                        Annotated::new(context, meta),
                        processor,
                        info,
                    ).map(Context::App)
                }
                Annotated(Some(Context::Browser(context)), meta) => {
                    ProcessAnnotatedValue::process_annotated_value(
                        Annotated::new(context, meta),
                        processor,
                        info,
                    ).map(Context::Browser)
                }
                Annotated(Some(Context::Other(name, context)), meta) => {
                    let Annotated(context, meta) = ProcessAnnotatedValue::process_annotated_value(
                        Annotated::new(context, meta),
                        processor,
                        info,
                    );
                    Annotated::new(Context::Other(name, context.unwrap_or_default()), meta)
                }
                other @ Annotated(None, _) => other,
            }
        }
    }
}

#[cfg(test)]
mod test_contexts {
    use super::super::tracked::TrackedDeserializer;
    use super::*;
    use serde_json;

    #[test]
    fn test_device_roundtrip() {
        let json = r#"{
  "type": "device",
  "name": "iphone",
  "family": "iphone",
  "model": "iphone7,3",
  "model_id": "AH223",
  "arch": "arm64",
  "battery_level": 58.5,
  "orientation": "landscape",
  "simulator": true,
  "memory_size": 3137978368,
  "free_memory": 322781184,
  "usable_memory": 2843525120,
  "storage_size": 63989469184,
  "free_storage": 31994734592,
  "external_storage_size": 2097152,
  "external_free_storage": 2097152,
  "boot_time": 1518094332,
  "timezone": "Europe/Vienna",
  "other": "value"
}"#;
        let context = Context::Device(Box::new(DeviceContext {
            name: Some("iphone".to_string()).into(),
            family: Some("iphone".to_string()).into(),
            model: Some("iphone7,3".to_string()).into(),
            model_id: Some("AH223".to_string()).into(),
            arch: Some("arm64".to_string()).into(),
            battery_level: Some(58.5).into(),
            orientation: Some("landscape".to_string()).into(),
            simulator: Some(true).into(),
            memory_size: Some(3_137_978_368).into(),
            free_memory: Some(322_781_184).into(),
            usable_memory: Some(2_843_525_120).into(),
            storage_size: Some(63_989_469_184).into(),
            free_storage: Some(31_994_734_592).into(),
            external_storage_size: Some(2_097_152).into(),
            external_free_storage: Some(2_097_152).into(),
            boot_time: Some("2018-02-08T12:52:12Z".parse().unwrap()).into(),
            timezone: Some("Europe/Vienna".to_string()).into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        }));

        assert_eq_dbg!(context, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&context).unwrap());
    }

    #[test]
    fn test_device_default_values() {
        let json = r#"{"type":"device"}"#;
        let context = Context::Device(Box::new(DeviceContext {
            name: None.into(),
            family: None.into(),
            model: None.into(),
            model_id: None.into(),
            arch: None.into(),
            battery_level: None.into(),
            orientation: None.into(),
            simulator: None.into(),
            memory_size: None.into(),
            free_memory: None.into(),
            usable_memory: None.into(),
            storage_size: None.into(),
            free_storage: None.into(),
            external_storage_size: None.into(),
            external_free_storage: None.into(),
            boot_time: None.into(),
            timezone: None.into(),
            other: Default::default(),
        }));

        assert_eq_dbg!(context, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&context).unwrap());
    }

    #[test]
    fn test_os_roundtrip() {
        let json = r#"{
  "type": "os",
  "name": "iOS",
  "version": "11.4.2",
  "build": "FEEDFACE",
  "kernel_version": "17.4.0",
  "rooted": true,
  "raw_description": "iOS 11.4.2 FEEDFACE (17.4.0)",
  "other": "value"
}"#;
        let context = Context::Os(Box::new(OsContext {
            name: Some("iOS".to_string()).into(),
            version: Some("11.4.2".to_string()).into(),
            build: Some("FEEDFACE".to_string()).into(),
            kernel_version: Some("17.4.0".to_string()).into(),
            rooted: Some(true).into(),
            raw_description: Some("iOS 11.4.2 FEEDFACE (17.4.0)".to_string()).into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        }));

        assert_eq_dbg!(context, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&context).unwrap());
    }

    #[test]
    fn test_os_default_values() {
        let json = r#"{"type":"os"}"#;
        let context = Context::Os(Box::new(OsContext {
            name: None.into(),
            version: None.into(),
            build: None.into(),
            kernel_version: None.into(),
            rooted: None.into(),
            raw_description: None.into(),
            other: Default::default(),
        }));

        assert_eq_dbg!(context, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&context).unwrap());
    }

    #[test]
    fn test_runtime_roundtrip() {
        let json = r#"{
  "type": "runtime",
  "name": "rustc",
  "version": "1.27.0",
  "raw_description": "rustc 1.27.0 stable",
  "other": "value"
}"#;
        let context = Context::Runtime(Box::new(RuntimeContext {
            name: Some("rustc".to_string()).into(),
            version: Some("1.27.0".to_string()).into(),
            raw_description: Some("rustc 1.27.0 stable".to_string()).into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        }));

        assert_eq_dbg!(context, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&context).unwrap());
    }

    #[test]
    fn test_runtime_default_values() {
        let json = r#"{"type":"runtime"}"#;
        let context = Context::Runtime(Box::new(RuntimeContext {
            name: None.into(),
            version: None.into(),
            raw_description: None.into(),
            other: Default::default(),
        }));

        assert_eq_dbg!(context, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&context).unwrap());
    }

    #[test]
    fn test_app_roundtrip() {
        let json = r#"{
  "type": "app",
  "app_start_time": 1518128517,
  "device_app_hash": "4c793e3776474877ae30618378e9662a",
  "build_type": "testflight",
  "app_identifier": "foo.bar.baz",
  "app_name": "Baz App",
  "app_version": "1.0",
  "app_build": "100001",
  "other": "value"
}"#;
        let context = Context::App(Box::new(AppContext {
            app_start_time: Some("2018-02-08T22:21:57Z".parse().unwrap()).into(),
            device_app_hash: Some("4c793e3776474877ae30618378e9662a".to_string()).into(),
            build_type: Some("testflight".to_string()).into(),
            app_identifier: Some("foo.bar.baz".to_string()).into(),
            app_name: Some("Baz App".to_string()).into(),
            app_version: Some("1.0".to_string()).into(),
            app_build: Some("100001".to_string()).into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        }));

        assert_eq_dbg!(context, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&context).unwrap());
    }

    #[test]
    fn test_app_default_values() {
        let json = r#"{"type":"app"}"#;
        let context = Context::App(Box::new(AppContext {
            app_start_time: None.into(),
            device_app_hash: None.into(),
            build_type: None.into(),
            app_identifier: None.into(),
            app_name: None.into(),
            app_version: None.into(),
            app_build: None.into(),
            other: Default::default(),
        }));

        assert_eq_dbg!(context, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&context).unwrap());
    }
    #[test]
    fn test_browser_roundtrip() {
        let json = r#"{
  "type": "browser",
  "name": "Google Chrome",
  "version": "67.0.3396.99",
  "other": "value"
}"#;
        let context = Context::Browser(Box::new(BrowserContext {
            name: Some("Google Chrome".to_string()).into(),
            version: Some("67.0.3396.99".to_string()).into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        }));

        assert_eq_dbg!(context, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&context).unwrap());
    }

    #[test]
    fn test_browser_default_values() {
        let json = r#"{"type":"browser"}"#;
        let context = Context::Browser(Box::new(BrowserContext {
            name: None.into(),
            version: None.into(),
            other: Default::default(),
        }));

        assert_eq_dbg!(context, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&context).unwrap());
    }

    #[test]
    fn test_other_roundtrip() {
        let json = r#"{"type":"mytype","other":"value"}"#;
        let context = Context::Other("mytype".to_string(), {
            let mut map = Map::new();
            map.insert(
                "other".to_string(),
                Value::String("value".to_string()).into(),
            );
            map
        });

        assert_eq_dbg!(context, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&context).unwrap());
    }

    #[test]
    fn test_untagged_deserialize() {
        let json = r#"{"mytype": {"other": "value"}}"#;

        let context = Context::Other("mytype".to_string(), {
            let mut map = Map::new();
            map.insert(
                "other".to_string(),
                Value::String("value".to_string()).into(),
            );
            map
        });

        use std::collections::BTreeMap;
        let mut wrapper = BTreeMap::new();
        wrapper.insert("mytype".to_string(), context);

        let deserialized = Deserialize::deserialize(TrackedDeserializer::new(
            &mut serde_json::Deserializer::from_str(json),
            Default::default(),
        )).unwrap();

        assert_eq_dbg!(wrapper, deserialized);
    }

    #[test]
    fn test_fallback_roundtrip() {
        let input = r#"{"other":"value"}"#;
        let output = r#"{"type":"unknown","other":"value"}"#;
        let context = Context::Other("unknown".to_string(), {
            let mut map = Map::new();
            map.insert(
                "other".to_string(),
                Value::String("value".to_string()).into(),
            );
            map
        });

        assert_eq_dbg!(context, serde_json::from_str(input).unwrap());
        assert_eq_str!(output, serde_json::to_string(&context).unwrap());
    }
}

fn default_breadcrumb_type() -> Annotated<String> {
    "default".to_string().into()
}

/// A breadcrumb.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
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
        assert_eq_str!(json, serde_json::to_string_pretty(&breadcrumb).unwrap());
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

    #[test]
    fn test_invalid() {
        let breadcrumb: Annotated<Breadcrumb> = Annotated::from_error("missing field `timestamp`");
        assert_eq_dbg!(breadcrumb, serde_json::from_str("{}").unwrap());
    }
}

/// A register value.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct RegVal(pub u64);

impl_hex_serde!(RegVal, u64);

/// A memory address.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct Addr(pub u64);

impl_hex_serde!(Addr, u64);

/// Single frame in a stack trace.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct Frame {
    /// Name of the frame's function. This might include the name of a class.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub function: Annotated<Option<String>>,

    /// Potentially mangled name of the symbol as it appears in an executable.
    ///
    /// This is different from a function name by generally being the mangled
    /// name that appears natively in the binary.  This is relevant for languages
    /// like Swift, C++ or Rust.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub symbol: Annotated<Option<String>>,

    /// Name of the module the frame is contained in.
    ///
    /// Note that this might also include a class name if that is something the
    /// language natively considers to be part of the stack (for instance in Java).
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "freeform")]
    // TODO: Cap? This can be a FS path or a dotted path
    pub module: Annotated<Option<String>>,

    /// Name of the package that contains the frame.
    ///
    /// For instance this can be a dylib for native languages, the name of the jar
    /// or .NET assembly.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "freeform")]
    // TODO: Cap? This can be a FS path or a dotted path
    pub package: Annotated<Option<String>>,

    /// The source file name (basename only).
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "freeform", cap = "short_path")]
    pub filename: Annotated<Option<String>>,

    /// Absolute path to the source file.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "freeform", cap = "path")]
    pub abs_path: Annotated<Option<String>>,

    /// Line number within the source file.
    #[serde(default, rename = "lineno", skip_serializing_if = "utils::is_none")]
    pub line: Annotated<Option<u64>>,

    /// Column number within the source file.
    #[serde(default, rename = "colno", skip_serializing_if = "utils::is_none")]
    pub column: Annotated<Option<u64>>,

    /// Source code leading up to the current line.
    #[serde(default, rename = "pre_context", skip_serializing_if = "utils::is_empty_array")]
    pub pre_lines: Annotated<Array<String>>,

    /// Source code of the current line.
    #[serde(default, rename = "context_line", skip_serializing_if = "utils::is_none")]
    pub current_line: Annotated<Option<String>>,

    /// Source code of the lines after the current line.
    #[serde(default, rename = "post_context", skip_serializing_if = "utils::is_empty_array")]
    pub post_lines: Annotated<Array<String>>,

    /// Override whether this frame should be considered in-app.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub in_app: Annotated<Option<bool>>,

    /// Local variables in a convenient format.
    #[serde(default, skip_serializing_if = "utils::is_empty_map")]
    #[process_annotated_value(pii_kind = "databag")]
    pub vars: Annotated<Map<Value>>,

    /// Start address of the containing code module (image).
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub image_addr: Annotated<Option<Addr>>,

    /// Absolute address of the frame's CPU instruction.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub instruction_addr: Annotated<Option<Addr>>,

    /// Start address of the frame's function.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub symbol_addr: Annotated<Option<Addr>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

#[cfg(test)]
mod test_frame {
    use super::*;
    use serde_json;

    #[test]
    fn test_roundtrip() {
        let json = r#"{
  "function": "main",
  "symbol": "_main",
  "module": "app",
  "package": "/my/app",
  "filename": "myfile.rs",
  "abs_path": "/path/to",
  "lineno": 2,
  "colno": 42,
  "pre_context": [
    "fn main() {"
  ],
  "context_line": "unimplemented!()",
  "post_context": [
    "}"
  ],
  "in_app": true,
  "vars": {
    "variable": "value"
  },
  "image_addr": "0x400",
  "instruction_addr": "0x404",
  "symbol_addr": "0x404",
  "other": "value"
}"#;
        let frame = Frame {
            function: Some("main".to_string()).into(),
            symbol: Some("_main".to_string()).into(),
            module: Some("app".to_string()).into(),
            package: Some("/my/app".to_string()).into(),
            filename: Some("myfile.rs".to_string()).into(),
            abs_path: Some("/path/to".to_string()).into(),
            line: Some(2).into(),
            column: Some(42).into(),
            pre_lines: vec!["fn main() {".to_string().into()].into(),
            current_line: Some("unimplemented!()".to_string()).into(),
            post_lines: vec!["}".to_string().into()].into(),
            in_app: Some(true).into(),
            vars: {
                let mut map = Map::new();
                map.insert(
                    "variable".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
            image_addr: Some(Addr(0x400)).into(),
            instruction_addr: Some(Addr(0x404)).into(),
            symbol_addr: Some(Addr(0x404)).into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        };

        assert_eq_dbg!(frame, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&frame).unwrap());
    }

    #[test]
    fn test_default_values() {
        let json = "{}";
        let frame = Frame {
            function: None.into(),
            symbol: None.into(),
            module: None.into(),
            package: None.into(),
            filename: None.into(),
            abs_path: None.into(),
            line: None.into(),
            column: None.into(),
            pre_lines: Default::default(),
            current_line: None.into(),
            post_lines: Default::default(),
            in_app: None.into(),
            vars: Default::default(),
            image_addr: None.into(),
            instruction_addr: None.into(),
            symbol_addr: None.into(),
            other: Default::default(),
        };

        assert_eq_dbg!(frame, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&frame).unwrap());
    }
}

/// Stack trace containing a thread's frames.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct Stacktrace {
    /// List of frames in this stack trace (required).
    #[process_annotated_value]
    pub frames: Annotated<Array<Frame>>,

    /// Omitted segment of frames (start, end).
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub frames_omitted: Annotated<Option<(u64, u64)>>,

    /// Register values of the thread (top frame).
    #[serde(default, skip_serializing_if = "utils::is_empty_map")]
    pub registers: Annotated<Map<RegVal>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

#[cfg(test)]
mod test_stacktrace {
    use super::*;
    use serde_json;

    #[test]
    fn test_roundtrip() {
        let json = r#"{
  "frames": [],
  "frames_omitted": [
    0,
    2
  ],
  "registers": {
    "cspr": "0x20000000",
    "lr": "0x18a31aadc",
    "pc": "0x18a310ea4",
    "sp": "0x16fd75060"
  },
  "other": "value"
}"#;
        let stack = Stacktrace {
            frames: Array::new().into(),
            frames_omitted: Some((0, 2)).into(),
            registers: {
                let mut map = Map::new();
                map.insert("cspr".to_string(), RegVal(0x2000_0000).into());
                map.insert("lr".to_string(), RegVal(0x1_8a31_aadc).into());
                map.insert("pc".to_string(), RegVal(0x1_8a31_0ea4).into());
                map.insert("sp".to_string(), RegVal(0x1_6fd7_5060).into());
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
        };

        assert_eq_dbg!(stack, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&stack).unwrap());
    }

    #[test]
    fn test_default_values() {
        let json = r#"{"frames":[]}"#;
        let stack = Stacktrace {
            frames: Array::new().into(),
            frames_omitted: None.into(),
            registers: Map::new().into(),
            other: Default::default(),
        };

        assert_eq_dbg!(stack, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&stack).unwrap());
    }

    #[test]
    fn test_invalid() {
        let stack: Annotated<Stacktrace> = Annotated::from_error("missing field `frames`");
        assert_eq_dbg!(stack, serde_json::from_str("{}").unwrap());
    }
}

/// POSIX signal with optional extended data.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct CError {
    /// The error code as specified by ISO C99, POSIX.1-2001 or POSIX.1-2008.
    pub number: Annotated<i32>,

    /// Optional name of the errno constant.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub name: Annotated<Option<String>>,
}

/// Mach exception information.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct MachException {
    /// The mach exception type.
    #[serde(rename = "exception")]
    pub ty: Annotated<i32>,

    /// The mach exception code.
    pub code: Annotated<u64>,

    /// The mach exception subcode.
    pub subcode: Annotated<u64>,

    /// Optional name of the mach exception.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub name: Annotated<Option<String>>,
}

/// POSIX signal with optional extended data.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct PosixSignal {
    /// The POSIX signal number.
    pub number: Annotated<i32>,

    /// An optional signal code present on Apple systems.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub code: Annotated<Option<i32>>,

    /// Optional name of the errno constant.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub name: Annotated<Option<String>>,

    /// Optional name of the errno constant.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub code_name: Annotated<Option<String>>,
}

/// Operating system or runtime meta information to an exception mechanism.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Serialize)]
pub struct MechanismMeta {
    /// Optional ISO C standard error code.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub errno: Annotated<Option<CError>>,

    /// Optional POSIX signal number.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub signal: Annotated<Option<PosixSignal>>,

    /// Optional mach exception information.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub mach_exception: Annotated<Option<MachException>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    pub other: Annotated<Map<Value>>,
}

impl MechanismMeta {
    fn is_empty(&self) -> bool {
        utils::is_none(&self.errno)
            && utils::is_none(&self.signal)
            && utils::is_none(&self.mach_exception)
            && utils::is_empty_map(&self.other)
    }

    fn is_empty_annotated(annotated: &Annotated<Self>) -> bool {
        utils::skip_if(annotated, MechanismMeta::is_empty)
    }
}

/// The mechanism by which an exception was generated and handled.
#[derive(Debug, Clone, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct Mechanism {
    /// Mechanism type (required).
    #[serde(rename = "type")]
    pub ty: Annotated<String>,

    /// Human readable detail description.
    #[serde(skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "freeform", cap = "message")]
    pub description: Annotated<Option<String>>,

    /// Link to online resources describing this error.
    #[serde(skip_serializing_if = "utils::is_none")]
    pub help_link: Annotated<Option<String>>,

    /// Flag indicating whether this exception was handled.
    #[serde(skip_serializing_if = "utils::is_none")]
    pub handled: Annotated<Option<bool>>,

    /// Additional attributes depending on the mechanism type.
    #[serde(skip_serializing_if = "utils::is_empty_map")]
    #[process_annotated_value(pii_kind = "databag")]
    pub data: Annotated<Map<Value>>,

    /// Operating system or runtime meta information.
    #[serde(skip_serializing_if = "MechanismMeta::is_empty_annotated")]
    pub meta: Annotated<MechanismMeta>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

mod mechanism {
    use super::*;
    use serde::de::Error;
    use std::collections::BTreeMap;

    fn deserialize<E: Error>(map: BTreeMap<String, Content>) -> Result<Mechanism, E> {
        let mut ty = None;
        let mut description = None;
        let mut help_link = None;
        let mut handled = None;
        let mut data = None;
        let mut meta = None;
        let mut other: Map<Value> = Default::default();

        for (key, content) in map {
            let deserializer = ContentDeserializer::new(content);
            match key.as_str() {
                "type" => ty = Some(Deserialize::deserialize(deserializer)?),
                "description" => description = Some(Deserialize::deserialize(deserializer)?),
                "help_link" => help_link = Some(Deserialize::deserialize(deserializer)?),
                "handled" => handled = Some(Deserialize::deserialize(deserializer)?),
                "data" => data = Some(Deserialize::deserialize(deserializer)?),
                "meta" => meta = Some(Deserialize::deserialize(deserializer)?),
                _ => {
                    other.insert(key, Deserialize::deserialize(deserializer)?);
                }
            }
        }

        Ok(Mechanism {
            ty: ty.ok_or_else(|| E::custom("missing field `type`"))?,
            description: description.unwrap_or_default(),
            help_link: help_link.unwrap_or_default(),
            handled: handled.unwrap_or_default(),
            data: data.unwrap_or_default(),
            meta: meta.unwrap_or_default(),
            other: Annotated::from(other),
        })
    }

    #[derive(Deserialize)]
    pub struct LegacyMachException {
        pub exception: Annotated<i32>,
        pub code: Annotated<u64>,
        pub subcode: Annotated<u64>,
        #[serde(default)]
        pub exception_name: Annotated<Option<String>>,
    }

    impl LegacyMachException {
        fn convert(self) -> Option<MachException> {
            Some(MachException {
                ty: self.exception,
                code: self.code,
                subcode: self.subcode,
                name: self.exception_name,
            })
        }
    }

    #[derive(Deserialize)]
    pub struct LegacyPosixSignal {
        pub signal: Annotated<i32>,
        #[serde(default)]
        pub code: Annotated<Option<i32>>,
        #[serde(default)]
        pub name: Annotated<Option<String>>,
        #[serde(default)]
        pub code_name: Annotated<Option<String>>,
    }

    impl LegacyPosixSignal {
        fn convert(self) -> Option<PosixSignal> {
            Some(PosixSignal {
                number: self.signal,
                code: self.code,
                name: self.name,
                code_name: self.code_name,
            })
        }
    }

    fn deserialize_legacy<E: Error>(map: BTreeMap<String, Content>) -> Result<Mechanism, E> {
        let mut data = Map::<Value>::new();
        let mut meta = MechanismMeta::default();

        for (key, content) in map {
            let deserializer = ContentDeserializer::new(content);
            match key.as_str() {
                "posix_signal" => {
                    let de = Annotated::<LegacyPosixSignal>::deserialize(deserializer)?;
                    meta.signal = de.map(LegacyPosixSignal::convert);
                }
                "mach_exception" => {
                    let de = Annotated::<LegacyMachException>::deserialize(deserializer)?;
                    meta.mach_exception = de.map(LegacyMachException::convert)
                }
                _ => {
                    data.insert(key, Deserialize::deserialize(deserializer)?);
                }
            }
        }

        Ok(Mechanism {
            ty: "generic".to_string().into(),
            description: None.into(),
            help_link: None.into(),
            handled: None.into(),
            data: data.into(),
            meta: meta.into(),
            other: Default::default(),
        })
    }

    impl<'de> Deserialize<'de> for Mechanism {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let map = BTreeMap::deserialize(deserializer)?;
            if !map.is_empty() && !map.contains_key("type") {
                deserialize_legacy(map)
            } else {
                deserialize(map)
            }
        }
    }
}

#[cfg(test)]
mod test_mechanism {
    use super::*;
    use serde_json;

    #[test]
    fn test_roundtrip() {
        let json = r#"{
  "type": "mytype",
  "description": "mydescription",
  "help_link": "https://developer.apple.com/library/content/qa/qa1367/_index.html",
  "handled": false,
  "data": {
    "relevant_address": "0x1"
  },
  "meta": {
    "errno": {
      "number": 2,
      "name": "ENOENT"
    },
    "signal": {
      "number": 11,
      "code": 0,
      "name": "SIGSEGV",
      "code_name": "SEGV_NOOP"
    },
    "mach_exception": {
      "exception": 1,
      "code": 1,
      "subcode": 8,
      "name": "EXC_BAD_ACCESS"
    },
    "other": "value"
  },
  "other": "value"
}"#;
        let mechanism = Mechanism {
            ty: "mytype".to_string().into(),
            description: Some("mydescription".to_string()).into(),
            help_link: Some(
                "https://developer.apple.com/library/content/qa/qa1367/_index.html".to_string(),
            ).into(),
            handled: Some(false).into(),
            data: {
                let mut map = Map::new();
                map.insert(
                    "relevant_address".to_string(),
                    Value::String("0x1".to_string()).into(),
                );
                Annotated::from(map)
            },
            meta: MechanismMeta {
                errno: Some(CError {
                    number: 2.into(),
                    name: Some("ENOENT".to_string()).into(),
                }).into(),
                mach_exception: Some(MachException {
                    ty: 1.into(),
                    code: 1.into(),
                    subcode: 8.into(),
                    name: Some("EXC_BAD_ACCESS".to_string()).into(),
                }).into(),
                signal: Some(PosixSignal {
                    number: 11.into(),
                    code: Some(0).into(),
                    name: Some("SIGSEGV".to_string()).into(),
                    code_name: Some("SEGV_NOOP".to_string()).into(),
                }).into(),
                other: {
                    let mut map = Map::new();
                    map.insert(
                        "other".to_string(),
                        Value::String("value".to_string()).into(),
                    );
                    Annotated::from(map)
                },
            }.into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        };

        assert_eq_dbg!(mechanism, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&mechanism).unwrap());
    }

    #[test]
    fn test_default_values() {
        let json = r#"{"type":"mytype"}"#;
        let mechanism = Mechanism {
            ty: "mytype".to_string().into(),
            description: None.into(),
            help_link: None.into(),
            handled: None.into(),
            data: Map::new().into(),
            meta: MechanismMeta::default().into(),
            other: Default::default(),
        };

        assert_eq_dbg!(mechanism, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&mechanism).unwrap());
    }

    #[test]
    fn test_invalid() {
        let mechanism: Annotated<Mechanism> = Annotated::from_error("missing field `type`");
        assert_eq_dbg!(mechanism, serde_json::from_str("{}").unwrap());
    }

    #[test]
    fn test_invalid_mechanisms() {
        let json = r#"{
  "type":"mytype",
  "meta": {
    "errno": {},
    "mach_exception": {},
    "signal": {}
  }
}"#;
        let mechanism = Mechanism {
            ty: "mytype".to_string().into(),
            description: None.into(),
            help_link: None.into(),
            handled: None.into(),
            data: Map::new().into(),
            meta: MechanismMeta {
                errno: Annotated::from_error("missing field `number`"),
                mach_exception: Annotated::from_error("missing field `exception`"),
                signal: Annotated::from_error("missing field `number`"),
                other: Default::default(),
            }.into(),
            other: Default::default(),
        };

        assert_eq_dbg!(mechanism, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_legacy_conversion() {
        let input = r#"{
  "posix_signal": {
    "name": "SIGSEGV",
    "code_name": "SEGV_NOOP",
    "signal": 11,
    "code": 0
  },
  "relevant_address": "0x1",
  "mach_exception": {
    "exception": 1,
    "exception_name": "EXC_BAD_ACCESS",
    "subcode": 8,
    "code": 1
  }
}"#;

        let output = r#"{
  "type": "generic",
  "data": {
    "relevant_address": "0x1"
  },
  "meta": {
    "signal": {
      "number": 11,
      "code": 0,
      "name": "SIGSEGV",
      "code_name": "SEGV_NOOP"
    },
    "mach_exception": {
      "exception": 1,
      "code": 1,
      "subcode": 8,
      "name": "EXC_BAD_ACCESS"
    }
  }
}"#;
        let mechanism = Mechanism {
            ty: "generic".to_string().into(),
            description: None.into(),
            help_link: None.into(),
            handled: None.into(),
            data: {
                let mut map = Map::new();
                map.insert(
                    "relevant_address".to_string(),
                    Value::String("0x1".to_string()).into(),
                );
                Annotated::from(map)
            },
            meta: MechanismMeta {
                errno: None.into(),
                mach_exception: Some(MachException {
                    ty: 1.into(),
                    code: 1.into(),
                    subcode: 8.into(),
                    name: Some("EXC_BAD_ACCESS".to_string()).into(),
                }).into(),
                signal: Some(PosixSignal {
                    number: 11.into(),
                    code: Some(0).into(),
                    name: Some("SIGSEGV".to_string()).into(),
                    code_name: Some("SEGV_NOOP".to_string()).into(),
                }).into(),
                other: Default::default(),
            }.into(),
            other: Default::default(),
        };

        assert_eq_dbg!(mechanism, serde_json::from_str(input).unwrap());
        assert_eq_str!(output, serde_json::to_string_pretty(&mechanism).unwrap());
    }
}

/// Identifier of a thread within an event.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[serde(untagged)]
pub enum ThreadId {
    /// Integer representation of the thread id.
    Int(u64),
    /// String representation of the thread id.
    String(String),
}

/// An exception (error).
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct Exception {
    /// Exception type (required).
    #[serde(rename = "type")]
    pub ty: Annotated<String>,

    /// Human readable display value.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "freeform", cap = "message")]
    pub value: Annotated<Option<String>>,

    /// Module name of this exception.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "freeform")]
    pub module: Annotated<Option<String>>,

    /// Stack trace containing frames of this exception.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value]
    pub stacktrace: Annotated<Option<Stacktrace>>,

    /// Optional unprocessed stack trace.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value]
    pub raw_stacktrace: Annotated<Option<Stacktrace>>,

    /// Identifier of the thread this exception occurred in.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub thread_id: Annotated<Option<ThreadId>>,

    /// Mechanism by which this exception was generated and handled.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value]
    pub mechanism: Annotated<Option<Mechanism>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

#[cfg(test)]
mod test_exception {
    use super::*;
    use serde_json;

    #[test]
    fn test_roundtrip() {
        // stack traces and mechanism are tested separately
        let json = r#"{
  "type": "mytype",
  "value": "myvalue",
  "module": "mymodule",
  "thread_id": 42,
  "other": "value"
}"#;
        let exception = Exception {
            ty: "mytype".to_string().into(),
            value: Some("myvalue".to_string()).into(),
            module: Some("mymodule".to_string()).into(),
            stacktrace: None.into(),
            raw_stacktrace: None.into(),
            thread_id: Some(ThreadId::Int(42)).into(),
            mechanism: None.into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        };

        assert_eq_dbg!(exception, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&exception).unwrap());
    }

    #[test]
    fn test_default_values() {
        let json = r#"{"type":"mytype"}"#;
        let exception = Exception {
            ty: "mytype".to_string().into(),
            value: None.into(),
            module: None.into(),
            stacktrace: None.into(),
            raw_stacktrace: None.into(),
            thread_id: None.into(),
            mechanism: None.into(),
            other: Default::default(),
        };

        assert_eq_dbg!(exception, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&exception).unwrap());
    }

    #[test]
    fn test_invalid() {
        let exception: Annotated<Exception> = Annotated::from_error("missing field `type`");
        assert_eq_dbg!(exception, serde_json::from_str("{}").unwrap());
    }
}

/// Template debug information.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct TemplateInfo {
    /// The file name (basename only).
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "freeform", cap = "short_path")]
    pub filename: Annotated<Option<String>>,

    /// Absolute path to the file.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(pii_kind = "freeform", cap = "path")]
    pub abs_path: Annotated<Option<String>>,

    /// Line number within the source file.
    #[serde(default, rename = "lineno", skip_serializing_if = "utils::is_none")]
    pub line: Annotated<Option<u64>>,

    /// Column number within the source file.
    #[serde(default, rename = "colno", skip_serializing_if = "utils::is_none")]
    pub column: Annotated<Option<u64>>,

    /// Source code leading up to the current line.
    #[serde(default, rename = "pre_context", skip_serializing_if = "utils::is_empty_array")]
    pub pre_lines: Annotated<Array<String>>,

    /// Source code of the current line.
    #[serde(default, rename = "context_line", skip_serializing_if = "utils::is_none")]
    pub current_line: Annotated<Option<String>>,

    /// Source code of the lines after the current line.
    #[serde(default, rename = "post_context", skip_serializing_if = "utils::is_empty_array")]
    pub post_lines: Annotated<Array<String>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

#[cfg(test)]
mod test_template_info {
    use super::*;
    use serde_json;

    #[test]
    fn test_roundtrip() {
        let json = r#"{
  "filename": "myfile.rs",
  "abs_path": "/path/to",
  "lineno": 2,
  "colno": 42,
  "pre_context": [
    "fn main() {"
  ],
  "context_line": "unimplemented!()",
  "post_context": [
    "}"
  ],
  "other": "value"
}"#;
        let template_info = TemplateInfo {
            filename: Some("myfile.rs".to_string()).into(),
            abs_path: Some("/path/to".to_string()).into(),
            line: Some(2).into(),
            column: Some(42).into(),
            pre_lines: vec!["fn main() {".to_string().into()].into(),
            current_line: Some("unimplemented!()".to_string()).into(),
            post_lines: vec!["}".to_string().into()].into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        };

        assert_eq_dbg!(template_info, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&template_info).unwrap());
    }

    #[test]
    fn test_default_values() {
        let json = "{}";
        let template_info = TemplateInfo {
            filename: None.into(),
            abs_path: None.into(),
            line: None.into(),
            column: None.into(),
            pre_lines: Default::default(),
            current_line: None.into(),
            post_lines: Default::default(),
            other: Default::default(),
        };

        assert_eq_dbg!(template_info, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&template_info).unwrap());
    }
}

/// A process thread of an event.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct Thread {
    /// Identifier of this thread within the process (usually an integer).
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub id: Annotated<Option<ThreadId>>,

    /// Display name of this thread.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value(cap = "summary")]
    pub name: Annotated<Option<String>>,

    /// Stack trace containing frames of this exception.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value]
    pub stacktrace: Annotated<Option<Stacktrace>>,

    /// Optional unprocessed stack trace.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    #[process_annotated_value]
    pub raw_stacktrace: Annotated<Option<Stacktrace>>,

    /// Indicates that this thread requested the event (usually by crashing).
    #[serde(default, skip_serializing_if = "utils::is_false")]
    pub crashed: Annotated<bool>,

    /// Indicates that the thread was not suspended when the event was created.
    #[serde(default, skip_serializing_if = "utils::is_false")]
    pub current: Annotated<bool>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

#[cfg(test)]
mod thread {
    use super::*;
    use serde_json;

    #[test]
    fn test_roundtrip() {
        // stack traces are tested separately
        let json = r#"{
  "id": 42,
  "name": "myname",
  "crashed": true,
  "current": true,
  "other": "value"
}"#;
        let thread = Thread {
            id: Some(ThreadId::Int(42)).into(),
            name: Some("myname".to_string()).into(),
            stacktrace: None.into(),
            raw_stacktrace: None.into(),
            crashed: true.into(),
            current: true.into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        };

        assert_eq_dbg!(thread, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&thread).unwrap());
    }

    #[test]
    fn test_default_values() {
        let json = "{}";
        let thread = Thread {
            id: None.into(),
            name: None.into(),
            stacktrace: None.into(),
            raw_stacktrace: None.into(),
            crashed: false.into(),
            current: false.into(),
            other: Default::default(),
        };

        assert_eq_dbg!(thread, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&thread).unwrap());
    }
}

/// Holds information about the system SDK.
///
/// This is relevant for iOS and other platforms that have a system
/// SDK.  Not to be confused with the client SDK.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct SystemSdkInfo {
    /// The internal name of the SDK.
    pub sdk_name: Annotated<String>,

    /// The major version of the SDK as integer or 0.
    pub version_major: Annotated<u32>,

    /// The minor version of the SDK as integer or 0.
    pub version_minor: Annotated<u32>,

    /// The patch version of the SDK as integer or 0.
    pub version_patchlevel: Annotated<u32>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

/// Apple debug image in
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct AppleDebugImage {
    /// Path and name of the debug image (required).
    pub name: Annotated<String>,

    /// CPU architecture target.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub arch: Annotated<Option<String>>,

    /// MachO CPU type identifier.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub cpu_type: Annotated<Option<u32>>,

    /// MachO CPU subtype identifier.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub cpu_subtype: Annotated<Option<u32>>,

    /// Starting memory address of the image (required).
    pub image_addr: Annotated<Addr>,

    /// Size of the image in bytes (required).
    pub image_size: Annotated<u64>,

    /// Loading address in virtual memory.
    #[serde(default = "debug_image::default_vmaddr")]
    pub image_vmaddr: Annotated<Addr>,

    /// The unique UUID of the image.
    pub uuid: Annotated<Uuid>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

/// Any debug information file supported by symbolic.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct SymbolicDebugImage {
    /// Path and name of the debug image (required).
    pub name: Annotated<String>,

    /// CPU architecture target.
    #[serde(default, skip_serializing_if = "utils::is_none")]
    pub arch: Annotated<Option<String>>,

    /// Starting memory address of the image (required).
    pub image_addr: Annotated<Addr>,

    /// Size of the image in bytes (required).
    pub image_size: Annotated<u64>,

    /// Loading address in virtual memory.
    #[serde(default = "debug_image::default_vmaddr")]
    pub image_vmaddr: Annotated<Addr>,

    /// Unique debug identifier of the image.
    pub id: Annotated<DebugId>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

/// Proguard mapping file.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct ProguardDebugImage {
    /// UUID computed from the file contents.
    pub uuid: Annotated<Uuid>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

/// A debug information file (debug image).
#[derive(Debug, Clone, PartialEq)]
pub enum DebugImage {
    /// Apple debug images (machos).  This is currently also used for non apple platforms with
    /// similar debug setups.
    Apple(Box<AppleDebugImage>),
    /// Symbolic (new style) debug infos.
    Symbolic(Box<SymbolicDebugImage>),
    /// A reference to a proguard debug file.
    Proguard(Box<ProguardDebugImage>),
    /// A debug image that is unknown to this protocol specification.
    Other(String, Map<Value>),
}

mod debug_image {
    use processor::{ProcessAnnotatedValue, Processor, ValueInfo};
    use std::borrow::Cow;

    use super::super::buffer::Content;
    use super::*;

    fn default_type() -> Cow<'static, str> {
        Cow::Borrowed("unknown")
    }

    pub fn default_vmaddr() -> Annotated<Addr> {
        Addr(0).into()
    }

    impl<'de> Deserialize<'de> for DebugImage {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            #[derive(Deserialize)]
            struct D<'a> {
                #[serde(default = "default_type", rename = "type")]
                t: Cow<'a, str>,
                #[serde(flatten, borrow)]
                content: Content<'a>,
            };

            let D { t, content } = D::deserialize(deserializer)?;
            let deserializer = ContentDeserializer::new(content);

            Ok(match t.as_ref() {
                "apple" => DebugImage::Apple(Deserialize::deserialize(deserializer)?),
                "symbolic" => DebugImage::Symbolic(Deserialize::deserialize(deserializer)?),
                "proguard" => DebugImage::Proguard(Deserialize::deserialize(deserializer)?),
                _ => DebugImage::Other(t.into_owned(), Deserialize::deserialize(deserializer)?),
            })
        }
    }

    impl Serialize for DebugImage {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            #[derive(Serialize)]
            struct S<'a, T: Serialize> {
                #[serde(rename = "type")]
                t: &'a str,
                #[serde(flatten)]
                image: T,
            }

            match self {
                DebugImage::Apple(ref apple) => S {
                    t: "apple",
                    image: apple,
                }.serialize(serializer),
                DebugImage::Symbolic(ref symbolic) => S {
                    t: "symbolic",
                    image: symbolic,
                }.serialize(serializer),
                DebugImage::Proguard(ref proguard) => S {
                    t: "proguard",
                    image: proguard,
                }.serialize(serializer),
                DebugImage::Other(ref name, ref other) => S {
                    t: name,
                    image: other,
                }.serialize(serializer),
            }
        }
    }

    impl ProcessAnnotatedValue for DebugImage {
        fn process_annotated_value(
            annotated: Annotated<Self>,
            processor: &Processor,
            info: &ValueInfo,
        ) -> Annotated<Self> {
            match annotated {
                Annotated(Some(DebugImage::Apple(image)), meta) => {
                    ProcessAnnotatedValue::process_annotated_value(
                        Annotated::new(image, meta),
                        processor,
                        info,
                    ).map(DebugImage::Apple)
                }
                Annotated(Some(DebugImage::Symbolic(image)), meta) => {
                    ProcessAnnotatedValue::process_annotated_value(
                        Annotated::new(image, meta),
                        processor,
                        info,
                    ).map(DebugImage::Symbolic)
                }
                Annotated(Some(DebugImage::Proguard(image)), meta) => {
                    ProcessAnnotatedValue::process_annotated_value(
                        Annotated::new(image, meta),
                        processor,
                        info,
                    ).map(DebugImage::Proguard)
                }
                Annotated(Some(DebugImage::Other(name, image)), meta) => {
                    let Annotated(image, meta) = ProcessAnnotatedValue::process_annotated_value(
                        Annotated::new(image, meta),
                        processor,
                        info,
                    );
                    Annotated::new(DebugImage::Other(name, image.unwrap_or_default()), meta)
                }
                other @ Annotated(None, _) => other,
            }
        }
    }
}

#[cfg(test)]
mod test_debug_image {
    use super::*;
    use serde_json;

    #[test]
    fn test_proguard_roundtrip() {
        let json = r#"{
  "type": "proguard",
  "uuid": "395835f4-03e0-4436-80d3-136f0749a893",
  "other": "value"
}"#;
        let image = DebugImage::Proguard(Box::new(ProguardDebugImage {
            uuid: "395835f4-03e0-4436-80d3-136f0749a893"
                .parse::<Uuid>()
                .unwrap()
                .into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        }));

        assert_eq_dbg!(image, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&image).unwrap());
    }

    #[test]
    fn test_apple_roundtrip() {
        let json = r#"{
  "type": "apple",
  "name": "CoreFoundation",
  "arch": "arm64",
  "cpu_type": 1233,
  "cpu_subtype": 3,
  "image_addr": "0x0",
  "image_size": 4096,
  "image_vmaddr": "0x8000",
  "uuid": "494f3aea-88fa-4296-9644-fa8ef5d139b6",
  "other": "value"
}"#;

        let image = DebugImage::Apple(Box::new(AppleDebugImage {
            name: "CoreFoundation".to_string().into(),
            arch: Some("arm64".to_string()).into(),
            cpu_type: Some(1233).into(),
            cpu_subtype: Some(3).into(),
            image_addr: Addr(0).into(),
            image_size: 4096.into(),
            image_vmaddr: Addr(32768).into(),
            uuid: "494f3aea-88fa-4296-9644-fa8ef5d139b6"
                .parse::<Uuid>()
                .unwrap()
                .into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        }));

        assert_eq_dbg!(image, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&image).unwrap());
    }

    #[test]
    fn test_apple_default_values() {
        let json = r#"{
  "type": "apple",
  "name": "CoreFoundation",
  "image_addr": "0x0",
  "image_size": 4096,
  "image_vmaddr": "0x8000",
  "uuid": "494f3aea-88fa-4296-9644-fa8ef5d139b6"
}"#;

        let image = DebugImage::Apple(Box::new(AppleDebugImage {
            name: "CoreFoundation".to_string().into(),
            arch: None.into(),
            cpu_type: None.into(),
            cpu_subtype: None.into(),
            image_addr: Addr(0).into(),
            image_size: 4096.into(),
            image_vmaddr: Addr(32768).into(),
            uuid: "494f3aea-88fa-4296-9644-fa8ef5d139b6"
                .parse::<Uuid>()
                .unwrap()
                .into(),
            other: Default::default(),
        }));

        assert_eq_dbg!(image, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&image).unwrap());
    }

    #[test]
    fn test_symbolic_roundtrip() {
        let json = r#"{
  "type": "symbolic",
  "name": "CoreFoundation",
  "arch": "arm64",
  "image_addr": "0x0",
  "image_size": 4096,
  "image_vmaddr": "0x8000",
  "id": "494f3aea-88fa-4296-9644-fa8ef5d139b6-1234",
  "other": "value"
}"#;

        let image = DebugImage::Symbolic(Box::new(SymbolicDebugImage {
            name: "CoreFoundation".to_string().into(),
            arch: Some("arm64".to_string()).into(),
            image_addr: Addr(0).into(),
            image_size: 4096.into(),
            image_vmaddr: Addr(32768).into(),
            id: "494f3aea-88fa-4296-9644-fa8ef5d139b6-1234"
                .parse::<DebugId>()
                .unwrap()
                .into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        }));

        assert_eq_dbg!(image, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&image).unwrap());
    }

    #[test]
    fn test_symbolic_default_values() {
        let json = r#"{
  "type": "symbolic",
  "name": "CoreFoundation",
  "image_addr": "0x0",
  "image_size": 4096,
  "image_vmaddr": "0x8000",
  "id": "494f3aea-88fa-4296-9644-fa8ef5d139b6-1234"
}"#;

        let image = DebugImage::Symbolic(Box::new(SymbolicDebugImage {
            name: "CoreFoundation".to_string().into(),
            arch: None.into(),
            image_addr: Addr(0).into(),
            image_size: 4096.into(),
            image_vmaddr: Addr(32768).into(),
            id: "494f3aea-88fa-4296-9644-fa8ef5d139b6-1234"
                .parse::<DebugId>()
                .unwrap()
                .into(),
            other: Default::default(),
        }));

        assert_eq_dbg!(image, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&image).unwrap());
    }

    #[test]
    fn test_other_roundtrip() {
        let json = r#"{"type":"mytype","other":"value"}"#;
        let image = DebugImage::Other("mytype".to_string(), {
            let mut map = Map::new();
            map.insert(
                "other".to_string(),
                Value::String("value".to_string()).into(),
            );
            map
        });

        assert_eq_dbg!(image, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&image).unwrap());
    }

    #[test]
    fn test_untagged_roundtrip() {
        let input = r#"{"other":"value"}"#;
        let output = r#"{"type":"unknown","other":"value"}"#;
        let image = DebugImage::Other("unknown".to_string(), {
            let mut map = Map::new();
            map.insert(
                "other".to_string(),
                Value::String("value".to_string()).into(),
            );
            map
        });

        assert_eq_dbg!(image, serde_json::from_str(input).unwrap());
        assert_eq_str!(output, serde_json::to_string(&image).unwrap());
    }
}

/// Debugging and processing meta information.
#[derive(Debug, Clone, Deserialize, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct DebugMeta {
    /// Information about the system SDK (e.g. iOS SDK).
    #[serde(default, rename = "sdk_info", skip_serializing_if = "utils::is_none")]
    #[process_annotated_value]
    pub system_sdk: Annotated<Option<SystemSdkInfo>>,

    /// List of debug information files (debug images).
    #[serde(default, skip_serializing_if = "utils::is_empty_array")]
    #[process_annotated_value]
    pub images: Annotated<Array<DebugImage>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    #[process_annotated_value(pii_kind = "databag")]
    pub other: Annotated<Map<Value>>,
}

#[cfg(test)]
mod test_debug_meta {
    use super::*;
    use serde_json;

    #[test]
    fn test_roundtrip() {
        // NOTE: images are tested separately
        let json = r#"{
  "sdk_info": {
    "sdk_name": "iOS",
    "version_major": 10,
    "version_minor": 3,
    "version_patchlevel": 0,
    "other": "value"
  },
  "other": "value"
}"#;
        let meta = DebugMeta {
            system_sdk: Some(SystemSdkInfo {
                sdk_name: "iOS".to_string().into(),
                version_major: 10.into(),
                version_minor: 3.into(),
                version_patchlevel: 0.into(),
                other: {
                    let mut map = Map::new();
                    map.insert(
                        "other".to_string(),
                        Value::String("value".to_string()).into(),
                    );
                    Annotated::from(map)
                },
            }).into(),
            images: Array::new().into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        };

        assert_eq_dbg!(meta, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&meta).unwrap());
    }

    #[test]
    fn test_default_values() {
        let json = "{}";
        let meta = DebugMeta {
            system_sdk: None.into(),
            images: Array::new().into(),
            other: Default::default(),
        };

        assert_eq_dbg!(meta, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string(&meta).unwrap());
    }
}

/// Information about the Sentry SDK.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct ClientSdkInfo {
    /// Unique SDK name.
    pub name: Annotated<String>,

    /// SDK version.
    pub version: Annotated<String>,

    /// List of integrations that are enabled in the SDK.
    #[serde(default, skip_serializing_if = "utils::is_empty_array")]
    pub integrations: Annotated<Array<String>>,

    /// Additional arbitrary fields for forwards compatibility.
    #[serde(flatten)]
    pub other: Annotated<Map<Value>>,
}

#[cfg(test)]
mod test_client_sdk {
    use super::*;
    use serde_json;

    #[test]
    fn test_roundtrip() {
        let json = r#"{
  "name": "sentry.rust",
  "version": "1.0.0",
  "integrations": [
    "actix"
  ],
  "other": "value"
}"#;
        let sdk = ClientSdkInfo {
            name: "sentry.rust".to_string().into(),
            version: "1.0.0".to_string().into(),
            integrations: vec!["actix".to_string().into()].into(),
            other: {
                let mut map = Map::new();
                map.insert(
                    "other".to_string(),
                    Value::String("value".to_string()).into(),
                );
                Annotated::from(map)
            },
        };

        assert_eq_dbg!(sdk, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&sdk).unwrap());
    }

    #[test]
    fn test_default_values() {
        let json = r#"{
  "name": "sentry.rust",
  "version": "1.0.0"
}"#;
        let sdk = ClientSdkInfo {
            name: "sentry.rust".to_string().into(),
            version: "1.0.0".to_string().into(),
            integrations: Array::new().into(),
            other: Default::default(),
        };

        assert_eq_dbg!(sdk, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&sdk).unwrap());
    }

    #[test]
    fn test_invalid() {
        let json = r#"{"name":"sentry.rust"}"#;
        let entry: Annotated<ClientSdkInfo> = Annotated::from_error("missing field `version`");
        assert_eq_dbg!(entry, serde_json::from_str(json).unwrap());
    }
}

mod fingerprint {
    use serde::de;

    use super::super::buffer::ContentDeserializer;
    use super::super::serde::CustomDeserialize;
    use super::*;

    struct Fingerprint(Option<String>);

    struct FingerprintVisitor;

    impl<'de> de::Visitor<'de> for FingerprintVisitor {
        type Value = Fingerprint;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a fingerprint value")
        }

        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
            Ok(Fingerprint(Some(
                if v { "True" } else { "False" }.to_string(),
            )))
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Fingerprint(Some(v.to_string())))
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(Fingerprint(Some(v.to_string())))
        }

        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
            Ok(Fingerprint(if v.abs() < (1i64 << 53) as f64 {
                Some(v.trunc().to_string())
            } else {
                None
            }))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Fingerprint(Some(v.to_string())))
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(Fingerprint(Some(v)))
        }
    }

    impl<'de> Deserialize<'de> for Fingerprint {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_any(FingerprintVisitor)
        }
    }

    struct FingerprintDeserialize;

    impl<'de> CustomDeserialize<'de, Vec<String>> for FingerprintDeserialize {
        fn deserialize<D>(deserializer: D) -> Result<Vec<String>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let content = ContentDeserializer::new(Content::deserialize(deserializer)?);
            Ok(Vec::<Fingerprint>::deserialize(content)?
                .into_iter()
                .filter_map(|f| f.0)
                .collect())
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
                Meta::from_error("invalid type: null, expected a fingerprint value")
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
    use std::collections::BTreeMap;

    use super::super::utils;
    use super::*;

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

    pub fn default_platform() -> Annotated<String> {
        "other".to_string().into()
    }

    pub fn is_default_fingerprint(annotated: &Annotated<Vec<String>>) -> bool {
        utils::skip_if(annotated, |f| {
            f.len() == 1 && (f[0] == "{{default}}" || f[0] == "{{ default }}")
        })
    }

    pub fn is_default_platform(annotated: &Annotated<String>) -> bool {
        utils::skip_if(annotated, |p| p == "other")
    }

    impl<'de> Deserialize<'de> for Event {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let mut id = None;
            let mut level = None;
            let mut fingerprint = None;
            let mut culprit = None;
            let mut transaction = None;
            let mut message = None;
            let mut logentry = None;
            let mut logger = None;
            let mut modules = None;
            let mut platform = None;
            let mut timestamp = None;
            let mut server_name = None;
            let mut release = None;
            let mut dist = None;
            let mut repos = None;
            let mut environment = None;
            let mut user = None;
            let mut request = None;
            let mut contexts = None;
            let mut breadcrumbs = None;
            let mut exceptions = None;
            let mut stacktrace = None;
            let mut template_info = None;
            let mut threads = None;
            let mut tags = None;
            let mut extra = None;
            let mut debug_meta = None;
            let mut client_sdk = None;
            let mut other: Map<Value> = Default::default();

            for (key, content) in BTreeMap::<String, Content>::deserialize(deserializer)? {
                if key.starts_with('_') {
                    continue;
                }

                let deserializer = ContentDeserializer::new(content);
                match key.as_str() {
                    "event_id" => id = Some(Deserialize::deserialize(deserializer)?),
                    "level" => level = Some(Deserialize::deserialize(deserializer)?),
                    "fingerprint" => fingerprint = Some(fingerprint::deserialize(deserializer)?),
                    "culprit" => culprit = Some(Deserialize::deserialize(deserializer)?),
                    "transaction" => transaction = Some(Deserialize::deserialize(deserializer)?),
                    "message" => message = Some(Deserialize::deserialize(deserializer)?),
                    "logentry" => logentry = Some(Deserialize::deserialize(deserializer)?),
                    "sentry.interfaces.Message" => if logentry.is_none() {
                        logentry = Some(Deserialize::deserialize(deserializer)?)
                    },
                    "logger" => logger = Some(Deserialize::deserialize(deserializer)?),
                    "modules" => modules = Some(Deserialize::deserialize(deserializer)?),
                    "platform" => platform = Some(Deserialize::deserialize(deserializer)?),
                    "timestamp" => timestamp = Some(serde_chrono::deserialize(deserializer)?),
                    "server_name" => server_name = Some(Deserialize::deserialize(deserializer)?),
                    "release" => release = Some(Deserialize::deserialize(deserializer)?),
                    "dist" => dist = Some(Deserialize::deserialize(deserializer)?),
                    "repos" => repos = Some(Deserialize::deserialize(deserializer)?),
                    "environment" => environment = Some(Deserialize::deserialize(deserializer)?),
                    "user" => user = Some(Deserialize::deserialize(deserializer)?),
                    "sentry.interfaces.User" => if user.is_none() {
                        user = Some(Deserialize::deserialize(deserializer)?);
                    },
                    "request" => request = Some(Deserialize::deserialize(deserializer)?),
                    "sentry.interfaces.Http" => if request.is_none() {
                        request = Some(Deserialize::deserialize(deserializer)?);
                    },
                    "contexts" => contexts = Some(Deserialize::deserialize(deserializer)?),
                    "sentry.interfaces.Contexts" => if contexts.is_none() {
                        contexts = Some(Deserialize::deserialize(deserializer)?);
                    },
                    "breadcrumbs" => breadcrumbs = Some(Deserialize::deserialize(deserializer)?),
                    "sentry.interfaces.Breadcrumbs" => if breadcrumbs.is_none() {
                        breadcrumbs = Some(Deserialize::deserialize(deserializer)?);
                    },
                    "exception" => exceptions = Some(Deserialize::deserialize(deserializer)?),
                    "sentry.interfaces.Exception" => if exceptions.is_none() {
                        exceptions = Some(Deserialize::deserialize(deserializer)?)
                    },
                    "stacktrace" => stacktrace = Some(Deserialize::deserialize(deserializer)?),
                    "sentry.interfaces.Stacktrace" => if stacktrace.is_none() {
                        stacktrace = Some(Deserialize::deserialize(deserializer)?)
                    },
                    "template" => template_info = Some(Deserialize::deserialize(deserializer)?),
                    "sentry.interfaces.Template" => if template_info.is_none() {
                        template_info = Some(Deserialize::deserialize(deserializer)?)
                    },
                    "threads" => threads = Some(Deserialize::deserialize(deserializer)?),
                    "sentry.interfaces.Threads" => if threads.is_none() {
                        threads = Some(Deserialize::deserialize(deserializer)?)
                    },
                    "tags" => tags = Some(Deserialize::deserialize(deserializer)?),
                    "extra" => extra = Some(Deserialize::deserialize(deserializer)?),
                    "debug_meta" => debug_meta = Some(Deserialize::deserialize(deserializer)?),
                    "sentry.interfaces.DebugMeta" => if debug_meta.is_none() {
                        debug_meta = Some(Deserialize::deserialize(deserializer)?)
                    },
                    "sdk" => client_sdk = Some(Deserialize::deserialize(deserializer)?),
                    _ => {
                        other.insert(key, Deserialize::deserialize(deserializer)?);
                    }
                }
            }

            Ok(Event {
                id: id.unwrap_or_default(),
                level: level.unwrap_or_default(),
                fingerprint: fingerprint.unwrap_or_else(fingerprint::default),
                culprit: culprit.unwrap_or_default(),
                transaction: transaction.unwrap_or_default(),
                message: message.unwrap_or_default(),
                logentry: logentry.unwrap_or_default(),
                logger: logger.unwrap_or_default(),
                modules: modules.unwrap_or_default(),
                platform: platform.unwrap_or_else(default_platform),
                timestamp: timestamp.unwrap_or_default(),
                server_name: server_name.unwrap_or_default(),
                release: release.unwrap_or_default(),
                dist: dist.unwrap_or_default(),
                repos: repos.unwrap_or_default(),
                environment: environment.unwrap_or_default(),
                user: user.unwrap_or_default(),
                request: request.unwrap_or_default(),
                contexts: contexts.unwrap_or_default(),
                breadcrumbs: breadcrumbs.unwrap_or_default(),
                exceptions: exceptions.unwrap_or_default(),
                stacktrace: stacktrace.unwrap_or_default(),
                template_info: template_info.unwrap_or_default(),
                threads: threads.unwrap_or_default(),
                tags: tags.unwrap_or_default(),
                extra: extra.unwrap_or_default(),
                debug_meta: debug_meta.unwrap_or_default(),
                client_sdk: client_sdk.unwrap_or_default(),
                other: Annotated::from(other),
            })
        }
    }
}

/// Represents a full event for Sentry.
#[derive(Debug, Clone, Default, PartialEq, ProcessAnnotatedValue, Serialize)]
pub struct Event {
    /// Unique identifier of this event.
    #[serde(
        rename = "event_id",
        skip_serializing_if = "utils::is_none",
        serialize_with = "event::serialize_id"
    )]
    pub id: Annotated<Option<Uuid>>,

    /// Severity level of the event.
    #[serde(skip_serializing_if = "utils::is_none")]
    pub level: Annotated<Option<Level>>,

    /// Manual fingerprint override.
    // XXX: This is a `Vec` and not `Array` intentionally
    #[serde(skip_serializing_if = "event::is_default_fingerprint")]
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

    /// Custom parameterized message for this event.
    #[serde(skip_serializing_if = "utils::is_none")]
    #[process_annotated_value]
    pub logentry: Annotated<Option<LogEntry>>,

    /// Logger that created the event.
    #[serde(skip_serializing_if = "utils::is_none")]
    pub logger: Annotated<Option<String>>,

    /// Name and versions of installed modules.
    #[serde(skip_serializing_if = "utils::is_empty_map")]
    pub modules: Annotated<Map<String>>,

    /// Platform identifier of this event (defaults to "other").
    #[serde(skip_serializing_if = "event::is_default_platform")]
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

    /// References to source code repositories.
    #[serde(skip_serializing_if = "utils::is_empty_map")]
    pub repos: Annotated<Map<RepoReference>>,

    /// Environment the environment was generated in ("production" or "development").
    #[serde(skip_serializing_if = "utils::is_none")]
    pub environment: Annotated<Option<String>>,

    /// Information about the user who triggered this event.
    #[serde(skip_serializing_if = "utils::is_none")]
    #[process_annotated_value]
    pub user: Annotated<Option<User>>,

    /// Information about a web request that occurred during the event.
    #[serde(skip_serializing_if = "utils::is_none")]
    #[process_annotated_value]
    pub request: Annotated<Option<Request>>,

    /// Contexts describing the environment (e.g. device, os or browser).
    #[serde(skip_serializing_if = "utils::is_empty_map")]
    #[process_annotated_value]
    pub contexts: Annotated<Map<Context>>,

    /// List of breadcrumbs recorded before this event.
    #[serde(skip_serializing_if = "utils::is_empty_values")]
    #[process_annotated_value]
    pub breadcrumbs: Annotated<Values<Breadcrumb>>,

    /// One or multiple chained (nested) exceptions.
    #[serde(rename = "exception", skip_serializing_if = "utils::is_empty_values")]
    #[process_annotated_value]
    pub exceptions: Annotated<Values<Exception>>,

    /// Deprecated event stacktrace.
    #[serde(skip_serializing_if = "utils::is_none")]
    #[process_annotated_value]
    pub stacktrace: Annotated<Option<Stacktrace>>,

    /// Simplified template error location information.
    #[serde(rename = "template", skip_serializing_if = "utils::is_none")]
    #[process_annotated_value]
    pub template_info: Annotated<Option<TemplateInfo>>,

    /// Threads that were active when the event occurred.
    #[serde(default, skip_serializing_if = "utils::is_empty_values")]
    #[process_annotated_value]
    pub threads: Annotated<Values<Thread>>,

    /// Custom tags for this event.
    #[serde(skip_serializing_if = "utils::is_empty_map")]
    #[process_annotated_value(pii_kind = "databag")]
    pub tags: Annotated<Map<String>>,

    /// Arbitrary extra information set by the user.
    #[serde(skip_serializing_if = "utils::is_empty_map")]
    #[process_annotated_value(pii_kind = "databag")]
    pub extra: Annotated<Map<Value>>,

    /// Meta data for event processing and debugging.
    #[serde(skip_serializing_if = "utils::is_none")]
    #[process_annotated_value]
    pub debug_meta: Annotated<Option<DebugMeta>>,

    /// Information about the Sentry SDK that generated this event.
    #[serde(rename = "sdk", skip_serializing_if = "utils::is_none")]
    pub client_sdk: Annotated<Option<ClientSdkInfo>>,

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
  "_meta": {
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
            level: Some(Level::Debug).into(),
            fingerprint: Annotated::from(vec!["myprint".to_string()]),
            culprit: Some("myculprit".to_string()).into(),
            transaction: Some("mytransaction".to_string()).into(),
            message: Some("mymessage".to_string()).into(),
            logentry: None.into(),
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
            repos: Default::default(),
            environment: Some("myenv".to_string()).into(),
            user: None.into(),
            request: None.into(),
            contexts: Default::default(),
            breadcrumbs: Default::default(),
            exceptions: Default::default(),
            stacktrace: None.into(),
            template_info: None.into(),
            threads: Default::default(),
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
            debug_meta: None.into(),
            client_sdk: None.into(),
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
        let json = "{}";
        let event = Annotated::from(Event {
            id: None.into(),
            level: None.into(),
            fingerprint: vec!["{{ default }}".to_string()].into(),
            culprit: None.into(),
            transaction: None.into(),
            message: None.into(),
            logentry: None.into(),
            logger: None.into(),
            modules: Default::default(),
            platform: "other".to_string().into(),
            timestamp: None.into(),
            server_name: None.into(),
            release: None.into(),
            dist: None.into(),
            repos: Default::default(),
            environment: None.into(),
            user: None.into(),
            request: None.into(),
            contexts: Default::default(),
            breadcrumbs: Default::default(),
            exceptions: Default::default(),
            stacktrace: None.into(),
            template_info: None.into(),
            threads: Default::default(),
            tags: Default::default(),
            extra: Default::default(),
            debug_meta: None.into(),
            client_sdk: None.into(),
            other: Default::default(),
        });

        assert_eq_dbg!(event, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, serde_json::to_string_pretty(&event).unwrap());
    }

    #[test]
    fn test_default_values_with_meta() {
        let json = r#"{
  "event_id": "52df9022835246eeb317dbd739ccd059",
  "fingerprint": [
    "{{ default }}"
  ],
  "platform": "other",
  "_meta": {
    "event_id": {
      "": {
        "err": [
          "some error"
        ]
      }
    },
    "fingerprint": {
      "": {
        "err": [
          "some error"
        ]
      }
    },
    "platform": {
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
            level: None.into(),
            fingerprint: Annotated::new(
                vec!["{{ default }}".to_string()],
                Meta::from_error("some error"),
            ),
            culprit: None.into(),
            transaction: None.into(),
            message: None.into(),
            logentry: None.into(),
            logger: None.into(),
            modules: Default::default(),
            platform: Annotated::new("other".to_string(), Meta::from_error("some error")),
            timestamp: None.into(),
            server_name: None.into(),
            release: None.into(),
            dist: None.into(),
            repos: Default::default(),
            environment: None.into(),
            user: None.into(),
            request: None.into(),
            contexts: Default::default(),
            breadcrumbs: Default::default(),
            exceptions: Default::default(),
            stacktrace: None.into(),
            template_info: None.into(),
            threads: Default::default(),
            tags: Default::default(),
            extra: Default::default(),
            debug_meta: None.into(),
            client_sdk: None.into(),
            other: Default::default(),
        });

        assert_eq_dbg!(event, deserialize(json).unwrap());
        assert_eq_str!(json, serialize(&event).unwrap());
    }
}
