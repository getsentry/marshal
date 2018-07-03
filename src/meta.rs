//! Event meta data.

use std::borrow::Cow;

use serde::{Deserialize, Deserializer};

use unexpected::UnexpectedType;

/// Description of a remark.
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, PartialEq)]
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
#[derive(Debug, PartialEq)]
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

/// Internal deserialization helper for potentially invalid data.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Maybe<T> {
    Valid(T),
    Invalid(UnexpectedType),
}

/// Wrapper for data fields with optional meta data.
#[derive(Debug, PartialEq)]
pub struct Annotated<T> {
    value: Option<T>,
    meta: Meta,
}

impl<T> Annotated<T> {
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

    /// The actual value.
    pub fn value(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Mutable reference to the actual value.
    pub fn value_mut(&mut self) -> Option<&mut T> {
        self.value.as_mut()
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

impl<T> From<Maybe<T>> for Annotated<T> {
    fn from(maybe: Maybe<T>) -> Self {
        match maybe {
            Maybe::Valid(value) => Annotated::from(value),
            Maybe::Invalid(u) => Annotated::from_error(format!("unexpected {}", u.0)),
        }
    }
}

impl<'de, T> Deserialize<'de> for Annotated<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Maybe::deserialize(deserializer)?.into())
    }
}

#[cfg(test)]
mod test_annotated {
    use super::*;
    use serde_json;

    #[derive(Debug, Default, Deserialize, PartialEq)]
    struct Test {
        answer: Annotated<i32>,
    }

    #[test]
    fn test_valid() {
        assert_eq!(Annotated::from(42), serde_json::from_str("42").unwrap());
    }

    #[test]
    fn test_valid_nested() {
        assert_eq!(
            Annotated::from(Test {
                answer: Annotated::from(42),
            }),
            serde_json::from_str(r#"{"answer": 42}"#).unwrap()
        );
    }

    #[test]
    fn test_invalid() {
        assert_eq!(
            Annotated::<i32>::from_error("unexpected null"),
            serde_json::from_str(r#"null"#).unwrap()
        );
    }

    #[test]
    fn test_invalid_nested() {
        assert_eq!(
            Annotated::from(Test {
                answer: Annotated::from_error("unexpected string")
            }),
            serde_json::from_str(r#"{"answer": "invalid"}"#).unwrap()
        );
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
