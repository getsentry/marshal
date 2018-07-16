//! Utilities for dealing with annotated strings.

use meta::{Meta, Remark, RemarkType};

/// A type for dealing with chunks of annotated text.
#[derive(Debug, Clone, PartialEq)]
pub enum Chunk {
    /// Unmodified text chunk.
    Text {
        /// The text value of the chunk
        text: String,
    },
    /// Redacted text chunk with a note.
    Redaction {
        /// The redacted text value
        text: String,
        /// The rule that crated this redaction
        rule_id: String,
        /// Type type of remark for this redaction
        ty: RemarkType,
    },
}

impl Chunk {
    /// The text of this chunk.
    pub fn as_str(&self) -> &str {
        match *self {
            Chunk::Text { ref text } => &text,
            Chunk::Redaction { ref text, .. } => &text,
        }
    }

    /// Effective length of the text in this chunk.
    pub fn len(&self) -> usize {
        self.as_str().len()
    }
}

/// Chunks the given text based on remarks.
pub fn chunks_from_str(text: &str, meta: &Meta) -> Vec<Chunk> {
    let mut rv = vec![];
    let mut pos = 0;

    for remark in meta.remarks() {
        let (start, end) = match remark.range() {
            Some(range) => range.clone(),
            None => continue,
        };

        if start > pos {
            if let Some(piece) = text.get(pos..start) {
                rv.push(Chunk::Text {
                    text: piece.to_string(),
                });
            } else {
                break;
            }
        }
        if let Some(piece) = text.get(start..end) {
            rv.push(Chunk::Redaction {
                text: piece.to_string(),
                rule_id: remark.rule_id().into(),
                ty: remark.ty(),
            });
        } else {
            break;
        }
        pos = end;
    }

    if pos < text.len() {
        if let Some(piece) = text.get(pos..) {
            rv.push(Chunk::Text {
                text: piece.to_string(),
            });
        }
    }

    rv
}

/// Concatenates chunks into a string and places remarks inside the given meta.
pub fn chunks_to_string(chunks: Vec<Chunk>, mut meta: Meta) -> (String, Meta) {
    let mut rv = String::new();
    let mut remarks = vec![];
    let mut pos = 0;

    for chunk in chunks {
        let new_pos = pos + chunk.len();
        rv.push_str(chunk.as_str());
        if let Chunk::Redaction {
            ref rule_id, ty, ..
        } = chunk
        {
            remarks.push(Remark::with_range(ty, rule_id.clone(), (pos, new_pos)));
        }
        pos = new_pos;
    }

    *meta.remarks_mut() = remarks;
    (rv, meta)
}
