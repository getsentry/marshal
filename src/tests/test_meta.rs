use serde::Serialize;
use serde_json;

use meta::{serialize_meta, Annotated, Meta, MetaMap, Remark, RemarkType};

mod test_meta_map {
    use super::*;

    #[test]
    fn test_empty() {
        assert_eq!(MetaMap::new(), serde_json::from_str("{}").unwrap());
    }

    #[test]
    fn test_root() {
        let json = r#"{
            "": {"err": ["a"]}
        }"#;

        let mut map = MetaMap::new();
        map.insert(".".to_string(), Meta::from_error("a"));

        assert_eq!(map, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_nested() {
        let json = r#"{
            "": {"err": ["a"]},
            "foo": {
                "": {"err": ["b"]},
                "bar": {
                    "": {"err": ["c"]}
                }
            }
        }"#;

        let mut map = MetaMap::new();
        map.insert(".".to_string(), Meta::from_error("a"));
        map.insert("foo".to_string(), Meta::from_error("b"));
        map.insert("foo.bar".to_string(), Meta::from_error("c"));

        assert_eq!(map, serde_json::from_str(json).unwrap());
    }
}

mod test_remarks {
    use super::*;

    #[test]
    fn test_rule_only() {
        let json = r#"["@test","a"]"#;
        let remark = Remark::new(RemarkType::Annotated, "@test");

        assert_eq!(remark, serde_json::from_str(json).unwrap());
        assert_eq!(json, &serde_json::to_string(&remark).unwrap());
    }

    #[test]
    fn test_with_description() {
        let json = r#"["test","x"]"#;
        let remark = Remark::new(RemarkType::Removed, "test");

        assert_eq!(remark, serde_json::from_str(json).unwrap());
        assert_eq!(json, &serde_json::to_string(&remark).unwrap());
    }

    #[test]
    fn test_with_range() {
        let json = r#"["@test","s",21,42]"#;
        let remark = Remark::with_range(RemarkType::Substituted, "@test", (21, 42));

        assert_eq!(remark, serde_json::from_str(json).unwrap());
        assert_eq!(json, &serde_json::to_string(&remark).unwrap());
    }

    #[test]
    fn test_with_additional() {
        let input = r#"["test","x",21,42,null]"#;
        let output = r#"["test","x",21,42]"#;
        let remark = Remark::with_range(RemarkType::Removed, "test", (21, 42));

        assert_eq!(remark, serde_json::from_str(input).unwrap());
        assert_eq!(output, &serde_json::to_string(&remark).unwrap());
    }
}

mod test_serialize_meta {
    use super::*;

    #[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
    struct Test {
        answer: Annotated<i32>,
    }

    fn serialize<T: Serialize>(value: &Annotated<T>) -> Result<String, serde_json::Error> {
        use serde::ser::Error;
        let tree = serialize_meta(value).map_err(serde_json::Error::custom)?;

        let mut serializer = serde_json::Serializer::new(Vec::new());
        tree.serialize(&mut serializer)?;

        Ok(String::from_utf8(serializer.into_inner()).unwrap())
    }

    #[test]
    fn test_empty() {
        let value = Annotated::<i32>::empty();
        assert_eq!(serialize(&value).unwrap(), "{}")
    }

    #[test]
    fn test_empty_nested() {
        let value = Annotated::from(Test {
            answer: Annotated::empty(),
        });

        assert_eq!(serialize(&value).unwrap(), "{}")
    }

    #[test]
    fn test_basic() {
        let value = Annotated::new(42, Meta::from_error("some error"));
        assert_eq!(serialize(&value).unwrap(), r#"{"":{"err":["some error"]}}"#);
    }

    #[test]
    fn test_nested() {
        let value = Annotated::new(
            Test {
                answer: Annotated::new(42, Meta::from_error("inner error")),
            },
            Meta::from_error("outer error"),
        );
        assert_eq!(
            serialize(&value).unwrap(),
            r#"{"":{"err":["outer error"]},"answer":{"":{"err":["inner error"]}}}"#
        );
    }

    #[test]
    fn test_array() {
        let value = Annotated::from(vec![
            Annotated::new(1, Meta::from_error("a")),
            Annotated::new(2, Meta::from_error("b")),
        ]);
        assert_eq!(
            serialize(&value).unwrap(),
            r#"{"0":{"":{"err":["a"]}},"1":{"":{"err":["b"]}}}"#
        );
    }
}
