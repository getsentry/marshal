use std::borrow::Cow;

use meta::{Meta, Note, Remark};

#[derive(Debug, Clone, PartialEq)]
pub enum Chunk<'a> {
    Text(Cow<'a, str>),
    Redaction(Cow<'a, str>, Note),
}

impl<'a> Chunk<'a> {
    pub fn as_str(&self) -> &str {
        match *self {
            Chunk::Text(ref text) => &text,
            Chunk::Redaction(ref text, ..) => &text,
        }
    }

    pub fn len(&self) -> usize {
        self.as_str().len()
    }
}

pub fn get_text_from_chunks<'a>(chunks: Vec<Chunk<'a>>, mut meta: Meta) -> (String, Meta) {
    let mut rv = String::new();
    let mut remarks = vec![];
    let mut pos = 0;

    for chunk in chunks {
        let new_pos = pos + chunk.len();
        rv.push_str(chunk.as_str());
        if let Chunk::Redaction(_, note) = chunk {
            remarks.push(Remark::new((pos, new_pos), note));
        }
        pos += new_pos;
    }

    *meta.remarks_mut() = remarks;
    (rv, meta)
}

pub fn get_chunks_from_text<'a>(text: &'a str, meta: &Meta) -> Vec<Chunk<'a>> {
    let mut rv = vec![];
    let mut pos = 0;

    for annotation in meta.remarks() {
        let (start, end) = annotation.range();
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
                annotation.note().clone(),
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

#[test]
fn test_chunking() {
    let chunks = get_chunks_from_text(
        "Hello Peter, my email address is ****@*****.com. See you",
        &Meta {
            remarks: vec![Remark::new(
                (33, 47),
                Note::new_well_known("@email-address"),
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
                Note::new_well_known("@email-address"),
            ),
            Chunk::Text(Cow::Borrowed(". See you")),
        ]
    );

    assert_eq!(
        get_text_from_chunks(chunks, Default::default()),
        (
            "Hello Peter, my email address is ****@*****.com. See you".into(),
            Meta {
                remarks: vec![Remark::new(
                    (33, 47),
                    Note::new_well_known("@email-address"),
                )],
                ..Default::default()
            }
        )
    );
}
