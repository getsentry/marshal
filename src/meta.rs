use std::borrow::Cow;

use serde::{Deserialize, Deserializer};

use unexpected::UnexpectedType;

#[derive(Debug, Clone, PartialEq)]
pub struct Note {
    rule: Cow<'static, str>,
    description: Option<Cow<'static, str>>,
}

impl Note {
    pub fn new(rule: String, description: String) -> Note {
        Note {
            rule: rule.into(),
            description: Some(description.into()),
        }
    }

    pub fn new_well_known(rule: &'static str) -> Note {
        Note {
            rule: Cow::Borrowed(rule),
            description: None,
        }
    }

    pub fn rule(&self) -> &str {
        &self.rule
    }

    pub fn description(&self) -> Option<&str> {
        if let Some(ref description) = self.description {
            Some(&description)
        } else {
            None
        }
    }
}

pub type Range = (usize, usize);

#[derive(Debug, PartialEq)]
pub struct Remark {
    range: Range,
    note: Note,
}

impl Remark {
    pub fn new(range: Range, note: Note) -> Self {
        Remark { range, note }
    }

    pub fn range(&self) -> Range {
        self.range
    }

    pub fn set_range(&mut self, range: Range) {
        self.range = range;
    }

    pub fn note(&self) -> &Note {
        &self.note
    }

    pub fn note_mut(&mut self) -> &mut Note {
        &mut self.note
    }
}

#[derive(Debug, PartialEq)]
pub struct Meta {
    // TODO: These should probably be pub
    pub(crate) remarks: Vec<Remark>,
    pub(crate) errors: Vec<String>,
    pub(crate) original_length: Option<u32>,
}

impl Meta {
    pub fn original_length(&self) -> Option<usize> {
        self.original_length.map(|x| x as usize)
    }

    pub fn set_original_length(&mut self, original_length: Option<u32>) {
        self.original_length = original_length;
    }

    pub fn remarks(&self) -> impl Iterator<Item = &Remark> {
        self.remarks.iter()
    }

    pub fn remarks_mut(&mut self) -> &mut Vec<Remark> {
        &mut self.remarks
    }

    pub fn errors(&self) -> impl Iterator<Item = &str> {
        self.errors.iter().map(|x| x.as_str())
    }

    pub fn errors_mut(&mut self) -> &mut Vec<String> {
        &mut self.errors
    }

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

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Maybe<T> {
    Valid(T),
    Invalid(UnexpectedType),
}

#[derive(Debug, PartialEq)]
pub struct Annotated<T> {
    value: T,
    meta: Meta,
}

impl<T> Annotated<T> {
    pub fn new(value: T, meta: Meta) -> Self {
        Annotated {
            value: value,
            meta: meta,
        }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    pub fn into_value(self) -> T {
        self.value
    }
}

impl<T: Default> Annotated<T> {
    pub fn error<S: Into<String>>(message: S) -> Self {
        Annotated {
            value: Default::default(),
            meta: Meta {
                remarks: Vec::new(),
                errors: vec![message.into()],
                original_length: None,
            },
        }
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

impl<T: Default> From<Maybe<T>> for Annotated<T> {
    fn from(maybe: Maybe<T>) -> Self {
        match maybe {
            Maybe::Valid(value) => Annotated::from(value),
            Maybe::Invalid(u) => Annotated::error(format!("unexpected {}", u.0)),
        }
    }
}

impl<'de, T> Deserialize<'de> for Annotated<T>
where
    T: Deserialize<'de> + Default,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Maybe::deserialize(deserializer)?.into())
    }
}
