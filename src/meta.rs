//! Event meta data.

use std::borrow::{self, Cow};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::iter::FromIterator;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::de::{self, Deserialize, Deserializer, IgnoredAny};
use serde::private::de::{Content, ContentDeserializer, ContentRepr};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

use forward::ForwardMapSerializer;
use tracked::{Path, TrackedDeserializer};
use utils::serde::{CustomDeserialize, CustomSerialize, DefaultDeserialize, DefaultSerialize};

/// Internal synchronization for meta data serialization.
thread_local!(static SERIALIZE_META: AtomicBool = AtomicBool::new(false));

/// Description of a remark.
#[derive(Clone, Debug, PartialEq)]
pub struct Note {
    rule: Cow<'static, str>,
    description: Option<Cow<'static, str>>,
}

impl Note {
    /// Creates a new Note.
    pub fn new<S, T>(rule: S, description: T) -> Note
    where
        S: Into<Cow<'static, str>>,
        T: Into<Cow<'static, str>>,
    {
        let rule = rule.into();
        let description = description.into();
        debug_assert!(!rule.starts_with("@"));

        Note {
            rule,
            description: Some(description),
        }
    }

    /// Creates a new well-known note without description.
    ///
    /// By convention, the rule name must start with "@".
    pub fn well_known(rule: &'static str) -> Note {
        debug_assert!(rule.starts_with("@"));

        Note {
            rule: Cow::Borrowed(rule),
            description: None,
        }
    }

    /// Returns the rule name of this note.
    pub fn rule(&self) -> &str {
        &self.rule
    }

    /// Returns the human readable description. Empty for well-known rules.
    pub fn description(&self) -> Option<&str> {
        if let Some(ref description) = self.description {
            Some(&description)
        } else {
            None
        }
    }

    /// Returns if this is a well-known rule.
    ///
    /// Such rules do not include a description.
    pub fn is_well_known(&self) -> bool {
        self.rule.starts_with("@")
    }
}

struct NoteVisitor;

impl<'de> de::Visitor<'de> for NoteVisitor {
    type Value = Note;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a meta note")
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let rule = seq
            .next_element()?
            .ok_or_else(|| de::Error::custom("missing required rule name"))?;
        let description = seq.next_element()?;

        // Drain the sequence
        while let Some(IgnoredAny) = seq.next_element()? {}

        Ok(Note { rule, description })
    }
}

impl<'de> Deserialize<'de> for Note {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(NoteVisitor)
    }
}

impl Serialize for Note {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let len = self.description().map_or(1, |_| 2);

        let mut seq = serializer.serialize_seq(Some(len))?;
        seq.serialize_element(self.rule())?;
        if let Some(description) = self.description() {
            seq.serialize_element(description)?;
        }

        seq.end()
    }
}

/// The start (inclusive) and end (exclusive) indices of a `Remark`.
pub type Range = (usize, usize);

/// Information on a modified section in a string.
#[derive(Clone, Debug, PartialEq)]
pub struct Remark {
    note: Note,
    range: Option<Range>,
}

impl Remark {
    /// Creates a new remark.
    pub fn new(note: Note) -> Self {
        Remark { note, range: None }
    }

    /// Creates a new text remark with range indices.
    pub fn with_range(note: Note, range: Range) -> Self {
        Remark {
            note,
            range: Some(range),
        }
    }

    /// The note of this remark.
    pub fn note(&self) -> &Note {
        &self.note
    }

    /// The mutable note of this remark.
    pub fn note_mut(&mut self) -> &mut Note {
        &mut self.note
    }

    /// The range of this remark.
    pub fn range(&self) -> Option<&Range> {
        self.range.as_ref()
    }

    /// Mutable range of this remark.
    pub fn range_mut(&mut self) -> Option<&mut Range> {
        self.range.as_mut()
    }

    /// Updates the range of this remark.
    pub fn set_range(&mut self, range: Option<Range>) {
        self.range = range;
    }

    /// The length of this range.
    pub fn len(&self) -> Option<usize> {
        self.range.map(|r| r.1 - r.0)
    }
}

struct RemarkVisitor;

impl<'de> de::Visitor<'de> for RemarkVisitor {
    type Value = Remark;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a meta remark")
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let note = seq
            .next_element()?
            .ok_or_else(|| de::Error::custom("missing required note"))?;
        let range = seq.next_element()?;

        // Drain the sequence
        while let Some(IgnoredAny) = seq.next_element()? {}

        Ok(Remark { note, range })
    }
}

impl<'de> Deserialize<'de> for Remark {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(RemarkVisitor)
    }
}

impl Serialize for Remark {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let len = self.range().map_or(1, |_| 2);

        let mut seq = serializer.serialize_seq(Some(len))?;
        seq.serialize_element(self.note())?;
        if let Some(range) = self.range() {
            seq.serialize_element(range)?;
        }

        seq.end()
    }
}

/// Meta information for a data field in the event payload.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Meta {
    /// Remarks detailling modifications of this field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remarks: Vec<Remark>,

    /// Errors that happened during deserialization or processing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,

    /// The original length of modified text fields or collections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_length: Option<u32>,
}

impl Meta {
    /// Creates a new meta data object from an error message.
    pub(crate) fn from_error<S: Into<String>>(message: S) -> Self {
        Meta {
            remarks: Vec::new(),
            errors: vec![message.into()],
            original_length: None,
        }
    }

    /// The original length of this field, if applicable.
    pub fn original_length(&self) -> Option<usize> {
        self.original_length.map(|x| x as usize)
    }

    /// Updates the original length of this annotation.
    pub fn set_original_length(&mut self, original_length: Option<u32>) {
        self.original_length = original_length;
    }

    /// Iterates all remarks on this field.
    pub fn remarks(&self) -> impl Iterator<Item = &Remark> {
        self.remarks.iter()
    }

    /// Mutable reference to remarks of this field.
    pub fn remarks_mut(&mut self) -> &mut Vec<Remark> {
        &mut self.remarks
    }

    /// Indicates whether this field has remarks.
    pub fn has_remarks(&self) -> bool {
        !self.remarks.is_empty()
    }

    /// Iterates errors on this field.
    pub fn errors(&self) -> impl Iterator<Item = &str> {
        self.errors.iter().map(|x| x.as_str())
    }

    /// Mutable reference to errors of this field.
    pub fn errors_mut(&mut self) -> &mut Vec<String> {
        &mut self.errors
    }

    /// Indicates whether this field has errors.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Indicates whether this field has meta data attached.
    pub fn is_empty(&self) -> bool {
        self.original_length.is_none() && self.remarks.is_empty() && self.errors.is_empty()
    }
}

impl Default for Meta {
    fn default() -> Meta {
        Meta {
            remarks: Vec::new(),
            errors: Vec::new(),
            original_length: None,
        }
    }
}

/// Wrapper for data fields with optional meta data.
#[derive(Debug, PartialEq, Clone)]
pub struct Annotated<T>(pub Option<T>, pub Meta);

impl<T> Annotated<T> {
    /// Creates an empty annotated shell without value or meta data.
    pub fn empty() -> Self {
        Annotated(None, Default::default())
    }

    /// Creates a new annotated value with meta data.
    pub fn new(value: T, meta: Meta) -> Self {
        Annotated(Some(value), meta)
    }

    /// Creates an annotated wrapper for invalid data with an error message.
    pub fn from_error<S: Into<String>>(message: S) -> Self {
        Annotated(None, Meta::from_error(message))
    }

    /// Custom deserialize implementation that merges meta data from the deserializer.
    pub fn deserialize_with<'de, D, C>(deserializer: D, _custom: C) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
        C: CustomDeserialize<'de, T>,
    {
        let mut annotated = {
            let mut annotated = Annotated::<T>::empty();

            let path: Option<&Rc<Path>> = deserializer.state().get();
            let meta_map: Option<&Rc<MetaMap>> = deserializer.state().get();
            if let (Some(path), Some(meta_map)) = (path, meta_map) {
                if let Some(meta) = meta_map.remove(&path.to_string()) {
                    *annotated.meta_mut() = meta;
                }
            }

            annotated
        };

        // Deserialize into a buffer first to catch syntax errors and fail fast. We use Serde's
        // private Content type instead of serde-value so we retain deserializer state.
        let content = Content::deserialize(deserializer)?;

        // Do not add an error to "meta" if the content is empty and there is already an error. This
        // would indicate that this field was previously validated and the value removed. Otherwise,
        // we would potentially generate error duplicates. We use the internal ContentRepr here to
        // avoid deserializing the content multiple times.
        let is_unit = match content.repr() {
            ContentRepr::Unit => true,
            _ => false,
        };

        // Continue deserialization into the target type. If this returns an error, we leave the
        // value as None and add the error to the meta data.
        match C::deserialize(ContentDeserializer::<D::Error>::new(content)) {
            Ok(value) => annotated.set_value(Some(value)),
            Err(err) => {
                if !is_unit || !annotated.meta().has_errors() {
                    annotated.meta_mut().errors_mut().push(err.to_string())
                }
            }
        }

        Ok(annotated)
    }

    /// Custom serialize implementation that optionally emits meta data.
    pub fn serialize_with<S, C>(&self, serializer: S, _custom: C) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        C: CustomSerialize<T>,
    {
        if SERIALIZE_META.with(|b| b.load(Ordering::Relaxed)) {
            let mut map = serializer.serialize_map(None)?;

            if !self.1.is_empty() {
                map.serialize_entry("", &self.1)?;
            }

            if let Some(ref value) = self.0 {
                C::serialize(value, ForwardMapSerializer(&mut map))?;
            }

            map.end()
        } else {
            match self.0 {
                Some(ref value) => C::serialize(value, serializer),
                None => serializer.serialize_unit(),
            }
        }
    }

    /// The actual value.
    pub fn value(&self) -> Option<&T> {
        self.0.as_ref()
    }

    /// Mutable reference to the actual value.
    pub fn value_mut(&mut self) -> Option<&mut T> {
        self.0.as_mut()
    }

    /// Update the value.
    pub fn set_value(&mut self, value: Option<T>) {
        self.0 = value;
    }

    /// Meta information on the value.
    pub fn meta(&self) -> &Meta {
        &self.1
    }

    /// Mutable reference to the value's meta information.
    pub fn meta_mut(&mut self) -> &mut Meta {
        &mut self.1
    }

    /// Transforms the value if it's set.
    pub fn map<F: FnOnce(T) -> T>(mut self, f: F) -> Self {
        self.0 = self.0.map(f);
        self
    }
}

impl<T: Default> Default for Annotated<T> {
    fn default() -> Self {
        Self::from(T::default())
    }
}

impl<T> From<T> for Annotated<T> {
    fn from(value: T) -> Self {
        Self::new(value, Default::default())
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Annotated<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Annotated::deserialize_with(deserializer, DefaultDeserialize::default())
    }
}

impl<T: Serialize> Serialize for Annotated<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.serialize_with(serializer, DefaultSerialize::default())
    }
}

/// A map of meta data entries for paths in a model.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MetaMap {
    inner: RefCell<BTreeMap<String, Meta>>,
}

impl MetaMap {
    /// Creates a new `MetaMap`.
    pub fn new() -> Self {
        MetaMap {
            inner: RefCell::new(BTreeMap::new()),
        }
    }

    /// Inserts a new meta entry into the map.
    pub fn insert(&mut self, path: String, meta: Meta) -> Option<Meta> {
        self.inner.borrow_mut().insert(path, meta)
    }

    /// Moves the meta entry for the given path to the caller.
    pub fn remove<P>(&self, path: &P) -> Option<Meta>
    where
        String: borrow::Borrow<P>,
        P: Ord + ?Sized,
    {
        self.inner.borrow_mut().remove(path)
    }
}

impl FromIterator<(String, Meta)> for MetaMap {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (String, Meta)>,
    {
        MetaMap {
            inner: RefCell::new(iter.into_iter().collect()),
        }
    }
}

#[derive(Debug, Default)]
struct MetaMapHelper(Vec<(String, Meta)>);

struct MetaMapVisitor(Option<String>);

impl<'de> de::Visitor<'de> for MetaMapVisitor {
    type Value = MetaMapHelper;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a meta data map")
    }

    fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let MetaMapVisitor(mut path) = self;
        let mut vec = Vec::new();

        while let Some(key) = map.next_key::<String>()? {
            if key.is_empty() {
                let meta = map.next_value()?;
                // The empty path can only occur once
                vec.push((path.take().unwrap(), meta));
            } else {
                let MetaMapHelper(entries) = map.next_value()?;
                vec.extend(entries);
            }
        }

        Ok(MetaMapHelper(vec))
    }
}

impl<'de> Deserialize<'de> for MetaMapHelper {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let path = deserializer.state().get().map(|p: &Rc<Path>| p.to_string());
        deserializer.deserialize_map(MetaMapVisitor(path))
    }
}

impl<'de> Deserialize<'de> for MetaMap {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tracked = TrackedDeserializer::new(deserializer, Default::default());
        let MetaMapHelper(entries) = MetaMapHelper::deserialize(tracked)?;
        Ok(entries.into_iter().collect())
    }
}

/// Deserializes an annotated value with given meta data.
pub fn deserialize<'de, D, T>(deserializer: D, meta_map: MetaMap) -> Result<Annotated<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let mut state = de::State::default();
    state.set(Rc::new(meta_map));

    let tracked = TrackedDeserializer::new(deserializer, state);
    Annotated::<T>::deserialize(tracked)
}

/// Serializes meta data of an annotated value into a nested map structure.
pub fn serialize_meta_with<T, S, F>(
    value: &Annotated<T>,
    serializer: S,
    serialize: F,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    F: FnOnce(&Annotated<T>, S) -> Result<S::Ok, S::Error>,
{
    SERIALIZE_META.with(|b| b.store(true, Ordering::Relaxed));
    let result = serialize(value, serializer);
    SERIALIZE_META.with(|b| b.store(false, Ordering::Relaxed));
    result
}

/// Serializes meta data of an annotated value into a nested map structure.
pub fn serialize_meta<T, S>(value: &Annotated<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    Annotated<T>: Serialize,
    S: Serializer,
{
    serialize_meta_with(value, serializer, Annotated::<T>::serialize)
}

#[cfg(test)]
mod test_annotated_with_meta {
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
        assert_eq!(value, deserialize(deserializer, meta_map).unwrap());
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
        assert_eq!(value, deserialize(deserializer, meta_map).unwrap());
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
        assert_eq!(value, deserialize(deserializer, meta_map).unwrap());
    }

    #[test]
    fn test_invalid() {
        let deserializer = &mut Deserializer::from_str("null");
        let mut meta_map = MetaMap::new();
        meta_map.insert(".".to_string(), Meta::from_error("some prior error"));

        // It should accept the "null" (unit) value and use the given error message
        let value = Annotated::<i32>::from_error("some prior error");
        assert_eq!(value, deserialize(deserializer, meta_map).unwrap());
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
        assert_eq!(value, deserialize(deserializer, meta_map).unwrap());
    }

    #[test]
    fn test_missing() {
        let deserializer = &mut Deserializer::from_str("null");

        // It should reject the "null" value and add an error
        let value = Annotated::<i32>::from_error("invalid type: null, expected i32");
        assert_eq!(value, deserialize(deserializer, MetaMap::new()).unwrap());
    }

    #[test]
    fn test_missing_nested() {
        let deserializer = &mut Deserializer::from_str(r#"{"answer":null, "other":21}"#);

        // It should reject the "null" value and add an error
        let value = Annotated::from(Test {
            answer: Annotated::from_error("invalid type: null, expected i32"),
            other: 21,
        });
        assert_eq!(value, deserialize(deserializer, MetaMap::new()).unwrap());
    }
}

#[cfg(test)]
mod test_annotated_without_meta {
    use super::*;
    use serde_json;

    #[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
    struct Test {
        answer: Annotated<i32>,
        other: i32,
    }

    #[test]
    fn test_valid() {
        let json = "42";
        let value = Annotated::from(42);

        assert_eq!(value, serde_json::from_str(json).unwrap());
        assert_eq!(json, &serde_json::to_string(&value).unwrap());
    }

    #[test]
    fn test_valid_nested() {
        let json = r#"{"answer":42,"other":21}"#;
        let value = Annotated::from(Test {
            answer: Annotated::from(42),
            other: 21,
        });

        assert_eq!(value, serde_json::from_str(json).unwrap());
        assert_eq!(json, &serde_json::to_string(&value).unwrap());
    }

    #[test]
    fn test_invalid() {
        let value = Annotated::<i32>::from_error("invalid type: map, expected i32");
        assert_eq!(value, serde_json::from_str(r#"{}"#).unwrap());
        assert_eq!("null", &serde_json::to_string(&value).unwrap());
    }

    #[test]
    fn test_invalid_nested() {
        let value = Annotated::from(Test {
            answer: Annotated::from_error("invalid type: string \"invalid\", expected i32"),
            other: 21,
        });

        assert_eq!(
            value,
            serde_json::from_str(r#"{"answer":"invalid","other":21}"#).unwrap()
        );
        assert_eq!(
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

#[cfg(test)]
mod test_meta_map {
    use super::*;
    use serde_json;

    #[test]
    fn test_empty() {
        assert_eq!(MetaMap::new(), serde_json::from_str("{}").unwrap());
    }

    #[test]
    fn test_root() {
        let json = r#"{
            "": {"errors": ["a"]}
        }"#;

        let mut map = MetaMap::new();
        map.insert(".".to_string(), Meta::from_error("a"));

        assert_eq!(map, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_nested() {
        let json = r#"{
            "": {"errors": ["a"]},
            "foo": {
                "": {"errors": ["b"]},
                "bar": {
                    "": {"errors": ["c"]}
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

#[cfg(test)]
mod test_remarks {
    use super::*;
    use serde_json;

    #[test]
    fn test_rule_only() {
        let json = r#"[["@test"]]"#;
        let remark = Remark::new(Note::well_known("@test"));

        assert_eq!(remark, serde_json::from_str(json).unwrap());
        assert_eq!(json, &serde_json::to_string(&remark).unwrap());
    }

    #[test]
    fn test_with_description() {
        let json = r#"[["test","my custom description"]]"#;
        let remark = Remark::new(Note::new("test", "my custom description"));

        assert_eq!(remark, serde_json::from_str(json).unwrap());
        assert_eq!(json, &serde_json::to_string(&remark).unwrap());
    }

    #[test]
    fn test_with_range() {
        let json = r#"[["@test"],[21,42]]"#;
        let remark = Remark::with_range(Note::well_known("@test"), (21, 42));

        assert_eq!(remark, serde_json::from_str(json).unwrap());
        assert_eq!(json, &serde_json::to_string(&remark).unwrap());
    }

    #[test]
    fn test_with_additional() {
        let input = r#"[["test","custom",null],[21,42],null]"#;
        let output = r#"[["test","custom"],[21,42]]"#;
        let remark = Remark::with_range(Note::new("test", "custom"), (21, 42));

        assert_eq!(remark, serde_json::from_str(input).unwrap());
        assert_eq!(output, &serde_json::to_string(&remark).unwrap());
    }
}
