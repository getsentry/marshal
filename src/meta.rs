//! Event meta data.

use std::borrow;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::iter::FromIterator;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::de::{self, Deserialize, Deserializer, IgnoredAny};
use serde::ser::{Serialize, SerializeSeq, Serializer};
use serde_json;

use meta_ser::{serialize_annotated_meta, MetaSerializer};
use protocol;
use tracked::{Path, TrackedDeserializer};
use utils::buffer::{Content, ContentDeserializer, ContentRepr};
use utils::serde::{CustomDeserialize, CustomSerialize, DefaultDeserialize, DefaultSerialize};

pub(crate) use meta_ser::{MetaError, MetaTree};

/// Internal synchronization for meta data serialization.
thread_local!(static SERIALIZE_META: AtomicBool = AtomicBool::new(false));

/// The start (inclusive) and end (exclusive) indices of a `Remark`.
pub type Range = (usize, usize);

/// Gives an indication about the type of remark.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemarkType {
    /// The remark just annotates a value but the value did not change.
    #[serde(rename = "a")]
    Annotated,
    /// The original value was removed entirely.
    #[serde(rename = "x")]
    Removed,
    /// The original value was substituted by a replacement value.
    #[serde(rename = "s")]
    Substituted,
    /// The original value was masked.
    #[serde(rename = "m")]
    Masked,
    /// The original value was replaced through pseudonymization.
    #[serde(rename = "p")]
    Pseudonymized,
    /// The original value was encrypted (not implemented yet).
    #[serde(rename = "e")]
    Encrypted,
}

/// Information on a modified section in a string.
#[derive(Clone, Debug, PartialEq)]
pub struct Remark {
    ty: RemarkType,
    rule_id: String,
    range: Option<Range>,
}

impl Remark {
    /// Creates a new remark.
    pub fn new<S: Into<String>>(ty: RemarkType, rule_id: S) -> Self {
        Remark {
            rule_id: rule_id.into(),
            ty: ty,
            range: None,
        }
    }

    /// Creates a new text remark with range indices.
    pub fn with_range<S: Into<String>>(ty: RemarkType, rule_id: S, range: Range) -> Self {
        Remark {
            rule_id: rule_id.into(),
            ty: ty,
            range: Some(range),
        }
    }

    /// The note of this remark.
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    /// The range of this remark.
    pub fn range(&self) -> Option<&Range> {
        self.range.as_ref()
    }

    /// The length of this range.
    pub fn len(&self) -> Option<usize> {
        self.range.map(|r| r.1 - r.0)
    }

    /// Returns the type.
    pub fn ty(&self) -> RemarkType {
        self.ty
    }
}

struct RemarkVisitor;

impl<'de> de::Visitor<'de> for RemarkVisitor {
    type Value = Remark;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a meta remark")
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let rule_id = seq.next_element()?
            .ok_or_else(|| de::Error::custom("missing required rule-id"))?;
        let ty = seq.next_element()?
            .ok_or_else(|| de::Error::custom("missing required remark-type"))?;
        let start = seq.next_element()?;
        let end = seq.next_element()?;

        // Drain the sequence
        while let Some(IgnoredAny) = seq.next_element()? {}

        let range = match (start, end) {
            (Some(start), Some(end)) => Some((start, end)),
            _ => None,
        };

        Ok(Remark { ty, rule_id, range })
    }
}

impl<'de> Deserialize<'de> for Remark {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(RemarkVisitor)
    }
}

impl Serialize for Remark {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(self.rule_id())?;
        seq.serialize_element(&self.ty())?;
        if let Some(range) = self.range() {
            seq.serialize_element(&range.0)?;
            seq.serialize_element(&range.1)?;
        }
        seq.end()
    }
}

/// Meta information for a data field in the event payload.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Meta {
    /// Remarks detailling modifications of this field.
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "rem")]
    pub remarks: Vec<Remark>,

    /// Errors that happened during deserialization or processing.
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "err")]
    pub errors: Vec<String>,

    /// The original length of modified text fields or collections.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "len")]
    pub original_length: Option<u32>,

    /// Path at which the annotated value was deserialized.
    #[serde(skip)]
    pub path: Option<Rc<Path>>,
}

impl PartialEq for Meta {
    fn eq(&self, other: &Self) -> bool {
        self.remarks == other.remarks
            && self.errors == other.errors
            && self.original_length == other.original_length
    }
}

impl Meta {
    /// Creates a new meta data object from an error message.
    pub fn from_error<S: Into<String>>(message: S) -> Self {
        Meta {
            remarks: Vec::new(),
            errors: vec![message.into()],
            original_length: None,
            path: None,
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

    /// Indicates that a null value is permitted for this field.
    pub fn null_is_valid(&self) -> bool {
        self.has_errors() || self.has_remarks()
    }

    /// Indicates whether this field has meta data attached.
    pub fn is_empty(&self) -> bool {
        self.original_length.is_none() && self.remarks.is_empty() && self.errors.is_empty()
    }

    /// The path at which the annotated value was deserialized.
    pub fn path(&self) -> Option<Rc<Path>> {
        self.path.clone()
    }

    /// Sets the path at which the annotated value was deserialized.
    fn set_path(&mut self, path: Option<Rc<Path>>) {
        self.path = path
    }
}

impl Default for Meta {
    fn default() -> Meta {
        Meta {
            remarks: Vec::new(),
            errors: Vec::new(),
            original_length: None,
            path: None,
        }
    }
}

/// Wrapper for data fields with optional meta data.
#[derive(Debug, PartialEq, Clone)]
pub struct Annotated<T>(pub Option<T>, pub Meta);

impl<'de, T: Deserialize<'de>> Annotated<T> {
    /// Deserializes an annotated from a JSON string.
    pub fn from_json(s: &'de str) -> Result<Annotated<T>, serde_json::Error> {
        protocol::from_str(s)
    }

    /// Deserializes an annotated from a deserializer
    pub fn deserialize_with_meta<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Annotated<T>, D::Error> {
        protocol::deserialize_with_meta(deserializer)
    }
}

impl<T: Serialize> Annotated<T> {
    /// Serializes an annotated value into a serializer.
    pub fn serialize_with_meta<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        protocol::serialize_with_meta(self, serializer)
    }

    /// Serializes an annotated value into a JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        protocol::to_string(self)
    }
}

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

            annotated.meta_mut().set_path(path.cloned());
            annotated
        };

        // Deserialize into a buffer first to catch syntax errors and fail fast. We use Serde's
        // private Content type instead of serde-value so we retain deserializer state.
        let content = Content::deserialize(deserializer)?;

        // Do not add an error to "meta" if the content is empty and there is already an error
        // or remakr. This would indicate that this field was previously validated and the value
        // removed by an error or processing. Otherwise, we would potentially generate error
        // duplicates. We use the internal ContentRepr here to avoid deserializing the content
        // multiple times.
        match content.repr() {
            ContentRepr::Unit if annotated.meta().null_is_valid() => return Ok(annotated),
            _ => (),
        };

        // Continue deserialization into the target type. If this returns an error, we leave the
        // value as None and add the error to the meta data.
        match C::deserialize(ContentDeserializer::<D::Error>::new(content)) {
            Ok(value) => annotated.set_value(Some(value)),
            Err(err) => annotated.meta_mut().errors_mut().push(err.to_string()),
        }

        Ok(annotated)
    }

    /// Custom serialize implementation that optionally emits meta data.
    pub fn serialize_with<S, C>(&self, serializer: S, serialize: C) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        C: CustomSerialize<T>,
    {
        if should_serialize_meta() {
            serialize_annotated_meta(self, serializer, serialize)
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

    /// Removes a value and writes a well known remark.
    pub fn with_removed_value(mut self, remark: Remark) -> Self {
        if self.0.is_some() {
            self.0 = None;
            self.1.remarks_mut().push(remark)
        }
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
    #[cfg(test)]
    pub fn new() -> Self {
        MetaMap {
            inner: RefCell::new(BTreeMap::new()),
        }
    }

    /// Inserts a new meta entry into the map.
    #[cfg(test)]
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
pub fn deserialize_meta<'de, D, T>(
    deserializer: D,
    meta_map: MetaMap,
) -> Result<Annotated<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let mut state = de::State::default();
    state.set(Rc::new(meta_map));

    let tracked = TrackedDeserializer::new(deserializer, state);
    Annotated::<T>::deserialize(tracked)
}

/// Indicates whether Annotated's meta data or values should be serialized.
pub(crate) fn should_serialize_meta() -> bool {
    SERIALIZE_META.with(|b| b.load(Ordering::Relaxed))
}

/// Serializes meta data of an annotated value into a nested map structure.
pub fn serialize_meta<T>(value: &Annotated<T>) -> Result<MetaTree, MetaError>
where
    Annotated<T>: Serialize,
{
    SERIALIZE_META.with(|b| b.store(true, Ordering::Relaxed));
    let tree = value.serialize(MetaSerializer)?;
    SERIALIZE_META.with(|b| b.store(false, Ordering::Relaxed));
    Ok(tree.unwrap_or_default())
}
