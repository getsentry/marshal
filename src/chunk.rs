use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq)]
pub struct Note {
    rule: Cow<'static, str>,
    description: Cow<'static, str>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Chunk<'a> {
    Text(Cow<'a, str>),
    Redaction(Cow<'a, str>, Option<Note>),
}

#[derive(Debug, PartialEq)]
pub struct Annotation {
    range: (i32, i32),
    note: Option<Note>,
}

#[derive(Debug, PartialEq)]
pub struct Meta {
    annotations: Vec<Annotation>,
    original_length: Option<u32>,
}

impl Note {
    pub fn new(rule: String, description: String) -> Note {
        Note {
            rule: rule.into(),
            description: description.into(),
        }
    }

    pub fn new_well_known(rule: &'static str) -> Note {
        Note {
            rule: Cow::Borrowed(rule),
            description: Cow::Borrowed(""),
        }
    }

    pub fn rule(&self) -> &str {
        &self.rule
    }

    pub fn description(&self) -> &str {
        &self.description
    }
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

impl Annotation {
    pub fn range(&self) -> (usize, usize) {
        (self.range.0 as usize, self.range.1 as usize)
    }
}

impl Default for Meta {
    fn default() -> Meta {
        Meta {
            annotations: vec![],
            original_length: None,
        }
    }
}

pub fn get_chunks_from_text<'a>(text: &'a str, meta: &Meta) -> Vec<Chunk<'a>> {
    let mut rv = vec![];
    let mut pos = 0;

    for annotation in &meta.annotations {
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
                annotation.note.clone(),
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

pub fn get_text_from_chunks<'a>(chunks: Vec<Chunk<'a>>, mut meta: Meta) -> (String, Meta) {
    let mut rv = String::new();
    let mut annotations = vec![];
    let mut pos = 0;

    for chunk in chunks {
        let new_pos = pos + chunk.len();
        rv.push_str(chunk.as_str());
        if let Chunk::Redaction(_, note) = chunk {
            annotations.push(Annotation {
                range: (pos as i32, new_pos as i32),
                note: note,
            });
        }
        pos += new_pos;
    }

    meta.annotations = annotations;
    (rv, meta)
}

#[test]
fn test_chunking() {
    let chunks = get_chunks_from_text(
        "Hello Peter, my email address is ****@*****.com. See you",
        &Meta {
            annotations: vec![Annotation {
                range: (33, 47),
                note: Some(Note::new_well_known("@email-address")),
            }],
            ..Default::default()
        },
    );

    assert_eq!(
        chunks,
        vec![
            Chunk::Text(Cow::Borrowed("Hello Peter, my email address is ")),
            Chunk::Redaction(
                Cow::Borrowed("****@*****.com"),
                Some(Note::new_well_known("@email-address")),
            ),
            Chunk::Text(Cow::Borrowed(". See you")),
        ]
    );

    assert_eq!(
        get_text_from_chunks(chunks, Default::default()),
        (
            "Hello Peter, my email address is ****@*****.com. See you".into(),
            Meta {
                annotations: vec![Annotation {
                    range: (33, 47),
                    note: Some(Note::new_well_known("@email-address")),
                }],
                ..Default::default()
            }
        )
    );
}
