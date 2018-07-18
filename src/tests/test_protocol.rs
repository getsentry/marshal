use serde_json;

use meta::{Annotated, Meta};
use protocol::*;

mod test_level {
    use super::*;

    #[test]
    fn test_log() {
        assert_eq_dbg!(Level::Info, serde_json::from_str("\"log\"").unwrap());
    }
}

mod test_breadcrumb {
    use super::*;
    use chrono::{TimeZone, Utc};

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

mod test_fingerprint {
    use super::*;
    use protocol::fingerprint;

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

mod test_event {
    use super::*;
    use chrono::{TimeZone, Utc};

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
