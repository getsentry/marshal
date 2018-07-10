//! Utilities for dealing with annotated strings.

use meta::{Meta, Note, Remark};

/// A type for dealing with chunks of annotated text.
#[derive(Debug, Clone, PartialEq)]
pub enum Chunk {
    /// Unmodified text chunk.
    Text(String),
    /// Redacted text chunk with a note.
    Redaction(String, Note),
}

impl Chunk {
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
pub fn from_str(text: &str, meta: &Meta) -> Vec<Chunk> {
    let mut rv = vec![];
    let mut pos = 0;

    for remark in meta.remarks() {
        let (start, end) = match remark.range() {
            Some(range) => range.clone(),
            None => continue,
        };

        if start > pos {
            if let Some(piece) = text.get(pos..start) {
                rv.push(Chunk::Text(piece.to_string()));
            } else {
                break;
            }
        }
        if let Some(piece) = text.get(start..end) {
            rv.push(Chunk::Redaction(piece.to_string(), remark.note().clone()));
        } else {
            break;
        }
        pos = end;
    }

    if pos < text.len() {
        if let Some(piece) = text.get(pos..) {
            rv.push(Chunk::Text(piece.to_string()));
        }
    }

    rv
}

/// Concatenates chunks into a string and places remarks inside the given meta.
pub fn to_string(chunks: Vec<Chunk>, mut meta: Meta) -> (String, Meta) {
    let mut rv = String::new();
    let mut remarks = vec![];
    let mut pos = 0;

    for chunk in chunks {
        let new_pos = pos + chunk.len();
        rv.push_str(chunk.as_str());
        if let Chunk::Redaction(_, note) = chunk {
            remarks.push(Remark::with_range(note, (pos, new_pos)));
        }
        pos += new_pos
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
            Chunk::Text("Hello Peter, my email address is ".into()),
            Chunk::Redaction("****@*****.com".into(), Note::well_known("@email-address")),
            Chunk::Text(". See you".into()),
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
