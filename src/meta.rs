//! Event meta data.

use std::borrow::{self, Cow};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use serde::private::de::{Content, ContentDeserializer, ContentRepr};
use serde::{de::State, Deserialize, Deserializer, Serialize, Serializer};

use tracked::{Path, TrackedDeserializer};
use utils::serde::{CustomDeserialize, DefaultDeserialize};

/// Description of a remark.
#[derive(Clone, Debug, PartialEq)]
pub struct Note {
    rule: Cow<'static, str>,
    description: Option<Cow<'static, str>>,
}

impl Note {
    /// Creates a new Note.
    pub fn new(rule: String, description: String) -> Note {
        debug_assert!(!rule.starts_with("@"));

        Note {
            rule: rule.into(),
            description: Some(description.into()),
        }
    }

    /// Creates a new well-known note without description.
    ///
    /// By convention, the rule name must start with "@".
    pub fn new_well_known(rule: &'static str) -> Note {
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
    pub fn well_known(&self) -> bool {
        self.rule.starts_with("@")
    }
}

/// The start (inclusive) and end (exclusive) indices of a `Remark`.
pub type Range = (usize, usize);

/// Information on a modified section in a string.
#[derive(Clone, Debug, PartialEq)]
pub struct Remark {
    range: (usize, usize),
    note: Note,
}

impl Remark {
    /// Creates a new remark.
    pub fn new(range: Range, note: Note) -> Self {
        Remark { range, note }
    }

    /// The range of this remark.
    pub fn range(&self) -> Range {
        self.range
    }

    /// Updates the range of this remark.
    pub fn set_range(&mut self, range: Range) {
        self.range = range;
    }

    /// The length of this range.
    pub fn len(&self) -> usize {
        self.range.1 - self.range.0
    }

    /// The note of this remark.
    pub fn note(&self) -> &Note {
        &self.note
    }

    /// The mutable note of this remark.
    pub fn note_mut(&mut self) -> &mut Note {
        &mut self.note
    }
}

/// Meta information for a data field in the event payload.
#[derive(Clone, Debug, PartialEq)]
pub struct Meta {
    // TODO: These should probably be pub, similar to structs in crate::protocol.
    pub(crate) remarks: Vec<Remark>,
    pub(crate) errors: Vec<String>,
    pub(crate) original_length: Option<u32>,
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
#[derive(Debug, PartialEq)]
pub struct Annotated<T> {
    value: Option<T>,
    meta: Meta,
}

impl<T> Annotated<T> {
    /// Creates an empty annotated shell without value or meta data.
    pub fn empty() -> Self {
        Annotated {
            value: None,
            meta: Default::default(),
        }
    }

    /// Creates a new annotated value with meta data.
    pub fn new(value: T, meta: Meta) -> Self {
        Annotated {
            value: Some(value),
            meta: meta,
        }
    }

    /// Creates an annotated wrapper for invalid data with an error message.
    pub fn from_error<S: Into<String>>(message: S) -> Self {
        Annotated {
            value: None,
            meta: Meta::from_error(message),
        }
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
            Ok(value) => *annotated.value_mut() = Some(value),
            Err(err) => {
                if !is_unit || !annotated.meta().has_errors() {
                    annotated.meta_mut().errors_mut().push(err.to_string())
                }
            }
        }

        Ok(annotated)
    }

    /// The actual value.
    pub fn value(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Mutable reference to the actual value.
    pub fn value_mut(&mut self) -> &mut Option<T> {
        &mut self.value
    }

    /// Meta information on the value.
    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// Mutable reference to the value's meta information.
    pub fn meta_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }

    /// Unwraps into the inner value.
    pub fn take(&mut self) -> Option<T> {
        self.value.take()
    }
}

impl<T: Default> Default for Annotated<T> {
    fn default() -> Self {
        T::default().into()
    }
}

impl<T> From<T> for Annotated<T> {
    fn from(value: T) -> Self {
        Self::new(value, Default::default())
    }
}

impl<'de, T> Deserialize<'de> for Annotated<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Annotated::deserialize_with(deserializer, DefaultDeserialize::default())
    }
}

impl<T: Serialize> Serialize for Annotated<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.value {
            Some(ref value) => value.serialize(serializer),
            None => serializer.serialize_unit(),
        }
    }
}

/// A map of meta data entries for paths in a model.
#[derive(Debug, Default)]
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

/// Deserializes an annotated type with given meta data.
pub fn deserialize<'de, D, T>(deserializer: D, meta_map: MetaMap) -> Result<Annotated<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let mut state = State::default();
    state.set(Rc::new(meta_map));

    let tracked = TrackedDeserializer::new(deserializer, state);
    Annotated::<T>::deserialize(tracked)
}

#[cfg(test)]
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
mod test_without_meta {
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
