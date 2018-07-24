//! Serde module for `chrono::DateTime`.

use std::fmt;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use serde::{de, ser};

use super::meta::Annotated;
use super::serde::{CustomDeserialize, CustomSerialize, ForwardSerialize};

pub fn timestamp_to_datetime(ts: f64) -> DateTime<Utc> {
    let secs = ts as i64;
    let micros = (ts.fract() * 1_000_000f64) as u32;
    Utc.timestamp_opt(secs, micros * 1000).unwrap()
}

struct SecondsTimestampVisitor;

impl<'de> de::Visitor<'de> for SecondsTimestampVisitor {
    type Value = DateTime<Utc>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a unix timestamp")
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Ok(timestamp_to_datetime(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Utc.timestamp_opt(value, 0).unwrap())
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Utc.timestamp_opt(value as i64, 0).unwrap())
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        match value.parse::<NaiveDateTime>() {
            Ok(dt) => Ok(DateTime::from_utc(dt, Utc)),
            Err(_) => value.parse(),
        }.map_err(|e| E::custom(format!("{}", e)))
    }
}

struct De(DateTime<Utc>);

impl<'de> de::Deserialize<'de> for De {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ok(De(deserializer
            .deserialize_any(SecondsTimestampVisitor)?
            .with_timezone(&Utc)))
    }
}

pub struct SerdeDateTime;

impl<'de> CustomDeserialize<'de, DateTime<Utc>> for SerdeDateTime {
    fn deserialize<D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        use serde::Deserialize;
        Ok(De::deserialize(deserializer)?.0)
    }
}

impl<'de> CustomDeserialize<'de, Option<DateTime<Utc>>> for SerdeDateTime {
    fn deserialize<D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        use serde::Deserialize;
        Ok(Option::<De>::deserialize(deserializer)?.map(|de| de.0))
    }
}

impl CustomSerialize<DateTime<Utc>> for SerdeDateTime {
    fn serialize<S>(datetime: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if datetime.timestamp_subsec_nanos() == 0 {
            serializer.serialize_i64(datetime.timestamp())
        } else {
            let micros = f64::from(datetime.timestamp_subsec_micros()) / 1_000_000f64;
            serializer.serialize_f64(datetime.timestamp() as f64 + micros)
        }
    }
}

impl CustomSerialize<Option<DateTime<Utc>>> for SerdeDateTime {
    fn serialize<S>(datetime: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        match datetime {
            Some(d) => serializer.serialize_some(&ForwardSerialize(d, SerdeDateTime)),
            None => serializer.serialize_none(),
        }
    }
}

pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Annotated<T>, D::Error>
where
    D: de::Deserializer<'de>,
    SerdeDateTime: CustomDeserialize<'de, T>,
{
    Annotated::deserialize_with(deserializer, SerdeDateTime)
}

pub fn serialize<T, S>(value: &Annotated<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: ser::Serializer,
    SerdeDateTime: CustomSerialize<T>,
{
    value.serialize_with(serializer, SerdeDateTime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Deserializer;

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
    fn test_date_with_timezone() {
        let deserializer = &mut Deserializer::from_str("\"2000-01-01T09:00:00+09:00\"");
        assert_eq_dbg!(
            deserialize(deserializer).unwrap(),
            Annotated::from(Utc.ymd(2000, 1, 1).and_hms(0, 0, 0))
        );
    }

    #[test]
    fn test_date_without_timezone() {
        let deserializer = &mut Deserializer::from_str("\"2000-01-01T00:00:00\"");
        assert_eq_dbg!(
            deserialize(deserializer).unwrap(),
            Annotated::from(Utc.ymd(2000, 1, 1).and_hms(0, 0, 0))
        );
    }

    #[test]
    fn test_invalid_date() {
        let deserializer = &mut Deserializer::from_str("\"invalid\"");
        assert_eq_dbg!(
            deserialize::<DateTime<Utc>, _>(deserializer).unwrap(),
            Annotated::from_error("input contains invalid characters")
        );
    }

    #[test]
    fn test_invalid_type() {
        let deserializer = &mut Deserializer::from_str("true");
        assert_eq_dbg!(
            deserialize::<DateTime<Utc>, _>(deserializer).unwrap(),
            Annotated::from_error("invalid type: boolean `true`, expected a unix timestamp")
        );
    }
}
