use serde_json;

use meta::Annotated;
use protocol::*;

#[test]
fn test_array() {
    let values = Values {
        values: vec![
            Value::from(1u64).into(),
            Value::from(2u64).into(),
            Value::from(3u64).into(),
        ].into(),
        other: Map::new().into(),
    };

    assert_eq_dbg!(values, serde_json::from_str("[1,2,3]").unwrap());
    assert_eq_str!(
        serde_json::to_string(&values).unwrap(),
        "{\"values\":[1,2,3]}"
    );
}

#[test]
fn test_object() {
    let values = Values {
        values: vec![
            Value::from(1u64).into(),
            Value::from(2u64).into(),
            Value::from(3u64).into(),
        ].into(),
        other: Map::new().into(),
    };

    assert_eq_dbg!(
        values,
        serde_json::from_str("{\"values\":[1,2,3]}").unwrap()
    );

    assert_eq_str!(
        serde_json::to_string(&values).unwrap(),
        "{\"values\":[1,2,3]}"
    );
}

#[test]
fn test_other() {
    let values = Values {
        values: vec![
            Value::from(1u64).into(),
            Value::from(2u64).into(),
            Value::from(3u64).into(),
        ].into(),
        other: {
            let mut m = Map::new();
            m.insert("foo".to_string(), Annotated::from(Value::from("bar")));
            Annotated::from(m)
        },
    };

    assert_eq_dbg!(
        values,
        serde_json::from_str("{\"values\":[1,2,3],\"foo\":\"bar\"}").unwrap()
    );

    assert_eq_str!(
        serde_json::to_string(&values).unwrap(),
        "{\"values\":[1,2,3],\"foo\":\"bar\"}"
    );
}

#[test]
fn test_option() {
    assert_eq_dbg!(
        None,
        serde_json::from_str::<Option<Values<u32>>>("null").unwrap()
    );
}

#[test]
fn test_empty() {
    assert!(Values::<u32>::new().is_empty());
    assert!(!Values::from(vec![1.into(), 2.into(), 3.into()]).is_empty())
}
