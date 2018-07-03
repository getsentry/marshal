use chrono::{DateTime, Utc};
use uuid::Uuid;

use common::Values;
use meta::Annotated;

pub mod serde_chrono {
    use std::fmt;

    use chrono::{DateTime, TimeZone, Utc};
    use serde::{de, ser};

    use meta::Annotated;

    fn timestamp_to_datetime(ts: f64) -> DateTime<Utc> {
        let secs = ts as i64;
        let micros = (ts.fract() * 1_000_000f64) as u32;
        Utc.timestamp_opt(secs, micros * 1000).unwrap()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Annotated<DateTime<Utc>>, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ok(deserializer
            .deserialize_any(SecondsTimestampVisitor)?
            .with_timezone(&Utc)
            .into())
    }

    pub fn serialize<S>(value: &Annotated<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let datetime = value.value();
        if datetime.timestamp_subsec_nanos() == 0 {
            serializer.serialize_i64(datetime.timestamp())
        } else {
            let micros = datetime.timestamp_subsec_micros() as f64 / 1_000_000f64;
            serializer.serialize_f64(datetime.timestamp() as f64 + micros)
        }
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
            value.parse().map_err(|e| E::custom(format!("{}", e)))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Breadcrumb {
    #[serde(with = "serde_chrono")]
    pub timestamp: Annotated<DateTime<Utc>>,
    pub ty: Annotated<String>,
    pub category: Annotated<Option<String>>,
}

impl Default for Breadcrumb {
    fn default() -> Self {
        // TODO: Implement defaults properly
        Breadcrumb {
            timestamp: Utc::now().into(),
            ty: "default".to_string().into(),
            category: None.into(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct Event {
    #[serde(default, rename = "event_id")]
    pub id: Annotated<Option<Uuid>>,
    #[serde(default)]
    pub breadcrumbs: Annotated<Values<Annotated<Breadcrumb>>>,
}
