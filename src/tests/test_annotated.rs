use serde_json;

use meta::{deserialize_meta, Annotated, Meta, MetaMap};
use tracked::TrackedDeserializer;

mod test_with_meta {
    use super::*;
    use serde_json::Deserializer;

    #[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
    struct Test {
        answer: Annotated<i32>,
        other: i32,
    }

    #[test]
    fn test_valid() {
        let deserializer = &mut Deserializer::from_str("42");
        let mut meta_map = MetaMap::new();
        meta_map.insert(".".to_string(), Meta::from_error("some prior error"));

        let value = Annotated::new(42, Meta::from_error("some prior error"));
        assert_eq_dbg!(value, deserialize_meta(deserializer, meta_map).unwrap());
    }

    #[test]
    fn test_valid_nested() {
        let deserializer = &mut Deserializer::from_str(r#"{"answer":42,"other":21}"#);
        let mut meta_map = MetaMap::new();
        meta_map.insert("answer".to_string(), Meta::from_error("some prior error"));

        let value = Annotated::from(Test {
            answer: Annotated::new(42, Meta::from_error("some prior error")),
            other: 21,
        });
        assert_eq_dbg!(value, deserialize_meta(deserializer, meta_map).unwrap());
    }

    #[test]
    fn test_valid_array() {
        let deserializer = &mut Deserializer::from_str(r#"[1,2]"#);
        let mut meta_map = MetaMap::new();
        meta_map.insert("0".to_string(), Meta::from_error("a"));
        meta_map.insert("1".to_string(), Meta::from_error("b"));

        let value = Annotated::from(vec![
            Annotated::new(1, Meta::from_error("a")),
            Annotated::new(2, Meta::from_error("b")),
        ]);
        assert_eq_dbg!(value, deserialize_meta(deserializer, meta_map).unwrap());
    }

    #[test]
    fn test_invalid() {
        let deserializer = &mut Deserializer::from_str("null");
        let mut meta_map = MetaMap::new();
        meta_map.insert(".".to_string(), Meta::from_error("some prior error"));

        // It should accept the "null" (unit) value and use the given error message
        let value = Annotated::<i32>::from_error("some prior error");
        assert_eq_dbg!(value, deserialize_meta(deserializer, meta_map).unwrap());
    }

    #[test]
    fn test_invalid_nested() {
        let deserializer = &mut Deserializer::from_str(r#"{"answer":null, "other":21}"#);
        let mut meta_map = MetaMap::new();
        meta_map.insert("answer".to_string(), Meta::from_error("some prior error"));

        // It should accept the "null" (unit) value and use the given error message
        let value = Annotated::from(Test {
            answer: Annotated::from_error("some prior error"),
            other: 21,
        });
        assert_eq_dbg!(value, deserialize_meta(deserializer, meta_map).unwrap());
    }

    #[test]
    fn test_missing() {
        let deserializer = &mut Deserializer::from_str("null");

        // It should reject the "null" value and add an error
        let value = Annotated::<i32>::from_error("invalid type: null, expected i32");
        assert_eq_dbg!(
            value,
            deserialize_meta(deserializer, MetaMap::new()).unwrap()
        );
    }

    #[test]
    fn test_missing_nested() {
        let deserializer = &mut Deserializer::from_str(r#"{"answer":null, "other":21}"#);

        // It should reject the "null" value and add an error
        let value = Annotated::from(Test {
            answer: Annotated::from_error("invalid type: null, expected i32"),
            other: 21,
        });
        assert_eq_dbg!(
            value,
            deserialize_meta(deserializer, MetaMap::new()).unwrap()
        );
    }
}

mod test_without_meta {
    use super::*;

    #[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
    struct Test {
        answer: Annotated<i32>,
        other: i32,
    }

    #[test]
    fn test_valid() {
        let json = "42";
        let value = Annotated::from(42);

        assert_eq_dbg!(value, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, &serde_json::to_string(&value).unwrap());
    }

    #[test]
    fn test_valid_nested() {
        let json = r#"{"answer":42,"other":21}"#;
        let value = Annotated::from(Test {
            answer: Annotated::from(42),
            other: 21,
        });

        assert_eq_dbg!(value, serde_json::from_str(json).unwrap());
        assert_eq_str!(json, &serde_json::to_string(&value).unwrap());
    }

    #[test]
    fn test_invalid() {
        let value = Annotated::<i32>::from_error("invalid type: map, expected i32");
        assert_eq_dbg!(value, serde_json::from_str(r#"{}"#).unwrap());
        assert_eq_str!("null", &serde_json::to_string(&value).unwrap());
    }

    #[test]
    fn test_invalid_nested() {
        let value = Annotated::from(Test {
            answer: Annotated::from_error("invalid type: string \"invalid\", expected i32"),
            other: 21,
        });

        assert_eq_dbg!(
            value,
            serde_json::from_str(r#"{"answer":"invalid","other":21}"#).unwrap()
        );
        assert_eq_str!(
            r#"{"answer":null,"other":21}"#,
            &serde_json::to_string(&value).unwrap()
        )
    }

    #[test]
    fn test_syntax_error() {
        assert!(serde_json::from_str::<i32>("nul").is_err());
    }

    #[test]
    fn test_syntax_error_nested() {
        assert!(serde_json::from_str::<Test>(r#"{"answer": nul}"#).is_err());
    }
}

mod test_meta_paths {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Test {
        answer: Annotated<i32>,
    }

    fn deserialize<'de, T: Deserialize<'de>>(string: &'de str) -> Result<T, serde_json::Error> {
        T::deserialize(TrackedDeserializer::new(
            &mut serde_json::Deserializer::from_str(string),
            Default::default(),
        ))
    }

    #[test]
    fn test_basic() {
        let value: Annotated<i32> = deserialize("42").unwrap();
        assert_eq_str!(".", value.meta().path().unwrap().to_string());
    }

    #[test]
    fn test_nested() {
        let value: Annotated<Test> = deserialize(r#"{"answer": 42}"#).unwrap();
        assert_eq_str!(
            "answer",
            value
                .value()
                .unwrap()
                .answer
                .meta()
                .path()
                .unwrap()
                .to_string()
        );
    }
}
