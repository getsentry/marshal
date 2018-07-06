//! Utilities for dealing with annotated strings.

use std::borrow::Cow;

use meta::{Meta, Note, Remark};

/// A type for dealing with chunks of annotated text.
#[derive(Debug, Clone, PartialEq)]
pub enum Chunk<'a> {
    /// Unmodified text chunk.
    Text(Cow<'a, str>),
    /// Redacted text chunk with a note.
    Redaction(Cow<'a, str>, Note),
}

impl<'a> Chunk<'a> {
    /// The text of this chunk.
    pub fn as_str(&self) -> &str {
        match *self {
            Chunk::Text(ref text) => &text,
            Chunk::Redaction(ref text, ..) => &text,
        }
    }

    /// Effective length of the text in this chunk.
    pub fn len(&self) -> usize {
        self.as_str().len()
    }
}

/// Chunks the given text based on remarks.
pub fn from_str<'a>(text: &'a str, meta: &Meta) -> Vec<Chunk<'a>> {
    let mut rv = vec![];
    let mut pos = 0;

    for remark in meta.remarks() {
        let (start, end) = match remark.range() {
            Some(range) => range.clone(),
            None => continue,
        };

        if start > pos {
            if let Some(piece) = text.get(pos..start) {
                rv.push(Chunk::Text(Cow::Borrowed(piece)));
            } else {
                break;
            }
        }
        if let Some(piece) = text.get(start..end) {
            rv.push(Chunk::Redaction(
                Cow::Borrowed(piece),
                remark.note().clone(),
            ));
        } else {
            break;
        }
        pos = end;
    }

    if pos < text.len() {
        if let Some(piece) = text.get(pos..) {
            rv.push(Chunk::Text(Cow::Borrowed(piece)));
        }
    }

    rv
}

/// Concatenates chunks into a string and places remarks inside the given meta.
pub fn to_string<'a>(chunks: Vec<Chunk<'a>>, mut meta: Meta) -> (String, Meta) {
    let mut rv = String::new();
    let mut remarks = vec![];
    let mut pos = 0;

    for chunk in chunks {
        let new_pos = pos + chunk.len();
        rv.push_str(chunk.as_str());
        if let Chunk::Redaction(_, note) = chunk {
            remarks.push(Remark::with_range(note, (pos, new_pos)));
        }
        pos += new_pos;
    }

    *meta.remarks_mut() = remarks;
    (rv, meta)
}

#[test]
fn test_chunking() {
    let chunks = from_str(
        "Hello Peter, my email address is ****@*****.com. See you",
        &Meta {
            remarks: vec![Remark::with_range(
                Note::well_known("@email-address"),
                (33, 47),
            )],
            ..Default::default()
        },
    );

    assert_eq!(
        chunks,
        vec![
            Chunk::Text(Cow::Borrowed("Hello Peter, my email address is ")),
            Chunk::Redaction(
                Cow::Borrowed("****@*****.com"),
                Note::well_known("@email-address"),
            ),
            Chunk::Text(Cow::Borrowed(". See you")),
        ]
    );

    assert_eq!(
        to_string(chunks, Default::default()),
        (
            "Hello Peter, my email address is ****@*****.com. See you".into(),
            Meta {
                remarks: vec![Remark::with_range(
                    Note::well_known("@email-address"),
                    (33, 47),
                )],
                ..Default::default()
            }
        )
    );
}
