use chrono::{TimeZone, Utc};
use serde_json::Deserializer;

use meta::Annotated;
use utils::serde_chrono::*;

#[test]
fn test_timestamp() {
    let deserializer = &mut Deserializer::from_str("946684800");
    assert_eq_dbg!(
        deserialize(deserializer).unwrap(),
        Annotated::from(Utc.ymd(2000, 1, 1).and_hms(0, 0, 0))
    );
}

#[test]
fn test_date() {
    let deserializer = &mut Deserializer::from_str("\"2000-01-01T00:00:00Z\"");
    assert_eq_dbg!(
        deserialize(deserializer).unwrap(),
        Annotated::from(Utc.ymd(2000, 1, 1).and_hms(0, 0, 0))
    );
}

#[test]
fn test_invalid_date() {
    let deserializer = &mut Deserializer::from_str("\"invalid\"");
    assert_eq_dbg!(
        deserialize(deserializer).unwrap(),
        Annotated::from_error("input contains invalid characters")
    );
}

#[test]
fn test_invalid_type() {
    let deserializer = &mut Deserializer::from_str("true");
    assert_eq_dbg!(
        deserialize(deserializer).unwrap(),
        Annotated::from_error("invalid type: boolean `true`, expected a unix timestamp")
    );
}
