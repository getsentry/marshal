//! PII stripping and normalization rule configuration.

use std::cmp;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use regex::{Regex, RegexBuilder};
use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer};

use chunk::{self, Chunk};
use common::Value;
use meta::{Annotated, Meta, Note, Remark};
use processor::{PiiKind, PiiProcessor, ProcessAnnotatedValue, ValueInfo};

lazy_static! {
    static ref NULL_SPLIT_RE: Regex = Regex::new("\x00").unwrap();
}

/// Indicates that the rule config was invalid after parsing.
#[derive(Fail, Debug)]
pub enum BadRuleConfig {
    /// An invalid reference to a rule was found in the config.
    #[fail(display = "invalid rule reference ({})", _0)]
    BadReference(String),
}

/// A regex pattern for text replacement.
pub struct Pattern(pub Regex);

impl fmt::Debug for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl Serialize for Pattern {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Pattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let pattern = RegexBuilder::new(&raw)
            .size_limit(262_144)
            .build()
            .map_err(Error::custom)?;
        Ok(Pattern(pattern))
    }
}

/// Supported stripping rules.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleType {
    /// Applies a regular expression.
    Pattern {
        /// The regular expression to apply.
        pattern: Pattern,
        /// The match group indices to replace.
        replace_groups: Option<BTreeSet<u8>>,
    },
    /// Unconditionally removes the value
    Remove,
    /// When a regex matches a key, a value is removed
    RemovePairValue {
        /// A pattern to match for keys.
        key_pattern: Pattern,
    },
}

/// Defines how replacements happen.
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged, rename_all = "snake_case")]
pub enum Replacement {
    /// Overwrites the matched groups with a mask.
    Mask {
        /// The character to mask with.
        mask_with_char: char,
        /// Characters to skip during masking to preserve structure.
        #[serde(default)]
        chars_to_ignore: String,
        /// Index range to mask in. Negative indices count from the string's end.
        #[serde(default)]
        mask_range: (Option<i32>, Option<i32>),
    },
    /// Replaces the matched group with a new value.
    NewValue {
        /// The replacement string.
        new_value: Value,
    },
}

fn in_range(range: (Option<i32>, Option<i32>), pos: usize, len: usize) -> bool {
    fn get_range_index(idx: Option<i32>, len: usize, default: usize) -> usize {
        match idx {
            None => default,
            Some(idx) if idx < 0 => len.saturating_sub((idx * -1) as usize),
            Some(idx) => cmp::min(idx as usize, len),
        }
    }

    let start = get_range_index(range.0, len, 0);
    let end = get_range_index(range.1, len, len);
    pos >= start && pos < end
}

impl Replacement {
    fn insert_replacement_chunks(&self, text: &str, note: Note, output: &mut Vec<Chunk>) {
        match *self {
            Replacement::Mask {
                mask_with_char,
                ref chars_to_ignore,
                mask_range,
            } => {
                let chars_to_ignore: BTreeSet<char> = chars_to_ignore.chars().collect();
                let mut buf = Vec::with_capacity(text.len());

                for (idx, c) in text.chars().enumerate() {
                    if in_range(mask_range, idx, text.len()) && !chars_to_ignore.contains(&c) {
                        buf.push(mask_with_char);
                    } else {
                        buf.push(c);
                    }
                }
                output.push(Chunk::Redaction(buf.into_iter().collect(), note));
            }
            Replacement::NewValue { ref new_value } => {
                output.push(Chunk::Redaction(new_value.to_string().into(), note));
            }
        }
    }

    fn set_replacement_value(
        &self,
        mut annotated: Annotated<Value>,
        note: Note,
    ) -> Annotated<Value> {
        match *self {
            Replacement::Mask { .. } => match annotated {
                Annotated(Some(value), meta) => {
                    let value_as_string = value.to_string();
                    let original_length = value_as_string.len();
                    let mut output = vec![];
                    self.insert_replacement_chunks(&value_as_string, note, &mut output);
                    let (value, mut meta) = chunk::chunks_to_string(output, meta);
                    if value.len() != original_length && meta.original_length.is_none() {
                        meta.original_length = Some(original_length as u32);
                    }
                    Annotated(Some(Value::String(value)), meta)
                }
                annotated @ Annotated(None, _) => annotated.with_removed_value(Remark::new(note)),
            },
            Replacement::NewValue { ref new_value } => {
                annotated.set_value(Some(new_value.clone()));
                annotated.meta_mut().remarks_mut().push(Remark::new(note));
                annotated
            }
        }
    }
}

/// A single rule configuration.
#[derive(Serialize, Deserialize, Debug)]
pub struct Rule {
    #[serde(flatten)]
    rule: RuleType,
    replace_with: Option<Replacement>,
    note: Option<String>,
}

/// A set of named rule configurations.
#[derive(Serialize, Deserialize, Debug)]
pub struct RuleConfig {
    rules: BTreeMap<String, Rule>,
    #[serde(default)]
    applications: BTreeMap<PiiKind, Vec<String>>,
}

/// A PII processor that uses JSON rules.
pub struct RuleBasedPiiProcessor<'a> {
    cfg: &'a RuleConfig,
    applications: BTreeMap<PiiKind, Vec<(&'a str, &'a Rule)>>,
}

impl Rule {
    fn insert_replacement_chunks(&self, text: &str, note: Note, output: &mut Vec<Chunk>) {
        if let Some(ref replace_with) = self.replace_with {
            replace_with.insert_replacement_chunks(text, note, output);
        } else {
            output.push(Chunk::Redaction("".to_string(), note));
        }
    }

    fn replace_value(&self, annotated: Annotated<Value>, note: Note) -> Annotated<Value> {
        if let Some(ref replace_with) = self.replace_with {
            replace_with.set_replacement_value(annotated, note)
        } else {
            annotated.with_removed_value(Remark::new(note))
        }
    }

    fn apply_to_chunks(
        &self,
        rule_id: &str,
        chunks: Vec<Chunk>,
        meta: Meta,
    ) -> Result<(Vec<Chunk>, Meta), (Vec<Chunk>, Meta)> {
        match self.rule {
            RuleType::Pattern {
                ref pattern,
                ref replace_groups,
            } => {
                let note = Note::new(rule_id.to_string(), self.note.clone());
                let mut search_string = String::new();
                let mut replacement_chunks = vec![];
                for chunk in chunks {
                    match chunk {
                        Chunk::Text(ref text) => search_string.push_str(&text.replace("\x00", "")),
                        chunk @ Chunk::Redaction(..) => {
                            replacement_chunks.push(chunk);
                            search_string.push('\x00');
                        }
                    }
                }
                replacement_chunks.reverse();
                let mut rv: Vec<Chunk> = vec![];

                fn process_text(
                    text: &str,
                    rv: &mut Vec<Chunk>,
                    replacement_chunks: &mut Vec<Chunk>,
                ) {
                    if text.is_empty() {
                        return;
                    }
                    let mut pos = 0;
                    for piece in NULL_SPLIT_RE.find_iter(text) {
                        rv.push(Chunk::Text(text[pos..piece.start()].to_string().into()));
                        rv.push(replacement_chunks.pop().unwrap());
                        pos = piece.end();
                    }
                    rv.push(Chunk::Text(text[pos..].to_string().into()));
                }

                let mut pos = 0;
                for m in pattern.0.captures_iter(&search_string) {
                    let g0 = m.get(0).unwrap();

                    match *replace_groups {
                        Some(ref groups) => {
                            for (idx, g) in m.iter().enumerate() {
                                if idx == 0 {
                                    continue;
                                }

                                if let Some(g) = g {
                                    if groups.contains(&(idx as u8)) {
                                        process_text(
                                            &search_string[pos..g.start()],
                                            &mut rv,
                                            &mut replacement_chunks,
                                        );
                                        self.insert_replacement_chunks(
                                            g.as_str(),
                                            note.clone(),
                                            &mut rv,
                                        );
                                        pos = g.end();
                                    }
                                }
                            }
                            process_text(&search_string[pos..], &mut rv, &mut replacement_chunks);
                        }
                        None => {
                            process_text(
                                &search_string[pos..g0.start()],
                                &mut rv,
                                &mut replacement_chunks,
                            );
                            self.insert_replacement_chunks(g0.as_str(), note.clone(), &mut rv);
                            pos = g0.end();
                        }
                    }

                    process_text(
                        &search_string[pos..g0.end()],
                        &mut rv,
                        &mut replacement_chunks,
                    );
                    pos = g0.end();
                }

                process_text(&search_string[pos..], &mut rv, &mut replacement_chunks);

                Ok((rv, meta))
            }
            // no special handling for strings, falls back to apply_to_value
            RuleType::Remove | RuleType::RemovePairValue { .. } => Err((chunks, meta)),
        }
    }

    fn apply_to_value(
        &self,
        rule_id: &str,
        value: Annotated<Value>,
        kind: PiiKind,
    ) -> Result<Annotated<Value>, Annotated<Value>> {
        let _kind = kind;
        match self.rule {
            // pattern matches are not implemented for non strings
            RuleType::Pattern { .. } => Err(value),
            RuleType::Remove => {
                let note = Note::new(rule_id.to_string(), self.note.clone());
                return Ok(self.replace_value(value, note));
            }
            RuleType::RemovePairValue { ref key_pattern } => {
                if let Some(ref path) = value.meta().path() {
                    if key_pattern.0.is_match(&path.to_string()) {
                        let note = Note::new(rule_id.to_string(), self.note.clone());
                        return Ok(self.replace_value(value, note));
                    }
                }
                Err(value)
            }
        }
    }
}

impl<'a> RuleBasedPiiProcessor<'a> {
    /// Creates a new rule based PII processor from a config.
    pub fn new(cfg: &'a RuleConfig) -> Result<RuleBasedPiiProcessor<'a>, BadRuleConfig> {
        let mut applications = BTreeMap::new();

        for (&pii_kind, cfg_applications) in &cfg.applications {
            let mut rules = vec![];
            for application in cfg_applications {
                if let Some(rule) = cfg.rules.get(application) {
                    rules.push((application.as_str(), rule));
                } else {
                    return Err(BadRuleConfig::BadReference(application.to_string()));
                }
            }
            applications.insert(pii_kind, rules);
        }

        Ok(RuleBasedPiiProcessor {
            cfg: cfg,
            applications: applications,
        })
    }

    /// Returns a reference to the config that created the processor.
    pub fn config(&self) -> &RuleConfig {
        self.cfg
    }

    /// Processes a root value (annotated event for instance)
    pub fn process_root_value<T: ProcessAnnotatedValue>(
        &self,
        value: Annotated<T>,
    ) -> Annotated<T> {
        ProcessAnnotatedValue::process_annotated_value(
            Annotated::from(value),
            self,
            &ValueInfo::default(),
        )
    }
}

impl<'a> PiiProcessor for RuleBasedPiiProcessor<'a> {
    fn pii_process_chunks(
        &self,
        chunks: Vec<Chunk>,
        meta: Meta,
        pii_kind: PiiKind,
    ) -> Result<(Vec<Chunk>, Meta), (Vec<Chunk>, Meta)> {
        let mut replaced = false;
        let mut rv = (chunks, meta);

        if let Some(rules) = self.applications.get(&pii_kind) {
            for (rule_id, rule) in rules {
                rv = match rule.apply_to_chunks(rule_id, rv.0, rv.1) {
                    Ok(val) => {
                        replaced = true;
                        val
                    }
                    Err(val) => val,
                };
            }
        }

        if replaced {
            Ok(rv)
        } else {
            Err(rv)
        }
    }

    fn pii_process_value(&self, mut value: Annotated<Value>, kind: PiiKind) -> Annotated<Value> {
        if let Some(rules) = self.applications.get(&kind) {
            for (rule_id, rule) in rules {
                value = match rule.apply_to_value(rule_id, value, kind) {
                    Ok(value) => return value,
                    Err(value) => value,
                };
            }
        }
        value
    }
}

#[test]
fn test_config() {
    use serde_json;
    let _cfg: RuleConfig = serde_json::from_str(r#"{
        "rules": {
            "path_username": {
                "type": "pattern",
                "pattern": "(?:\b[a-zA-Z]:)?(?:[/\\\\](users|home)[/\\\\])([^/\\\\]+)",
                "replace_groups": [1],
                "replace_with": {
                    "new_value": "[username]"
                },
                "note": "username in path"
            },
            "creditcard_numbers": {
                "type": "pattern",
                "pattern": "\\d{4}[- ]?\\d{4,6}[- ]?\\d{4,5}(?:[- ]?\\d{4})",
                "replace_with": {
                    "mask_with_char": "*",
                    "chars_to_ignore": "- ",
                    "mask_range": [6, -4]
                },
                "note": "creditcard number"
            },
            "email_address": {
                "type": "pattern",
                "pattern": "[a-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9-]+(\\.[a-z0-9-]+)*",
                "replace_with": {
                    "mask_with_char": "*",
                    "chars_to_ignore": "@."
                },
                "note": "potential email address"
            },
            "ipv4": {
                "type": "pattern",
                "pattern": "\\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b",
                "replace_with": {
                    "mask_with_char": "*",
                    "chars_to_ignore": "."
                },
                "note": "ip address"
            },
            "password_pairs": {
                "type": "remove_pair_value",
                "key_pattern": "password|pw|pword|pwd",
                "replace_with": {
                    "new_value": "[password]"
                },
                "note": "password"
            }
        },
        "applications": {
            "freeform": ["path_username", "creditcard_numbers", "email_address", "ipv4"],
            "databag": ["path_username", "creditcard_numbers", "email_address", "ipv4", "password_pairs"]
        }
    }"#).unwrap();
}

#[test]
fn test_basic_stripping() {
    use common::Map;
    use meta::Remark;
    use serde_json;

    let cfg: RuleConfig = serde_json::from_str(
        r#"{
        "rules": {
            "path_username": {
                "type": "pattern",
                "pattern": "(?i)(?:\b[a-zA-Z]:)?(?:[/\\\\](?:users|home)[/\\\\])([^/\\\\\\s]+)",
                "replace_groups": [1],
                "replace_with": {
                    "new_value": "[username]"
                },
                "note": "username in path"
            },
            "creditcard_number": {
                "type": "pattern",
                "pattern": "\\d{4}[- ]?\\d{4,6}[- ]?\\d{4,5}(?:[- ]?\\d{4})",
                "replace_with": {
                    "mask_with_char": "*",
                    "chars_to_ignore": "- ",
                    "mask_range": [0, -4]
                },
                "note": "creditcard number"
            },
            "email_address": {
                "type": "pattern",
                "pattern": "[a-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9-]+(\\.[a-z0-9-]+)*",
                "replace_with": {
                    "mask_with_char": "*",
                    "chars_to_ignore": "@."
                },
                "note": "potential email address"
            },
            "remove_foo": {
                "type": "remove_pair_value",
                "key_pattern": "foo",
                "replace_with": {
                    "new_value": "whatever"
                }
            },
            "remove_ip": {
                "type": "remove",
                "note": "IP address removed"
            }
        },
        "applications": {
            "freeform": ["path_username", "creditcard_number", "email_address"],
            "ip": ["remove_ip"],
            "databag": ["remove_foo"]
        }
    }"#,
    ).unwrap();

    #[derive(ProcessAnnotatedValue, Debug, Deserialize, Serialize, Clone)]
    struct Event {
        #[process_annotated_value(pii_kind = "freeform")]
        message: Annotated<String>,
        #[process_annotated_value(pii_kind = "databag")]
        extra: Annotated<Map<Value>>,
        #[process_annotated_value(pii_kind = "ip")]
        ip: Annotated<String>,
    }

    let event = Annotated::<Event>::from_str(r#"
        {
            "message": "Hello peter@gmail.com.  You signed up with card 1234-1234-1234-1234. Your home folder is C:\\Users\\peter. Look at our compliance",
            "extra": {
                "foo": 42,
                "bar": true
            },
            "ip": "192.168.1.1"
        }
    "#).unwrap();

    let processor = RuleBasedPiiProcessor::new(&cfg).unwrap();
    let processed_event = processor.process_root_value(event);
    let new_event = processed_event.clone().0.unwrap();

    let message = new_event.message.value().unwrap();
    assert_eq!(
        message,
        "Hello *****@*****.***.  You signed up with card ****-****-****-1234. \
         Your home folder is C:\\Users\\[username] Look at our compliance \
         Look at our compliance"
    );
    assert_eq!(
        new_event.message.meta(),
        &Meta {
            remarks: vec![
                Remark::with_range(
                    Note::new("email_address", Some("potential email address")),
                    (6, 21),
                ),
                Remark::with_range(
                    Note::new("creditcard_number", Some("creditcard number")),
                    (81, 100),
                ),
                Remark::with_range(
                    Note::new("path_username", Some("username in path")),
                    (393, 403),
                ),
            ],
            errors: vec![],
            original_length: Some(127),
            path: None,
        }
    );

    let foo = new_event.extra.value().unwrap().get("foo").unwrap();
    assert!(foo.value().is_none());
    assert_eq!(
        foo.meta(),
        &Meta {
            remarks: vec![Remark::new(Note::well_known("remove_foo"))],
            errors: vec![],
            original_length: None,
            path: None,
        }
    );

    let ip = &new_event.ip;
    assert!(ip.value().is_none());
    assert_eq!(
        ip.meta(),
        &Meta {
            remarks: vec![Remark::new(Note::new(
                "remove_ip",
                Some("IP address removed"),
            ))],
            errors: vec![],
            original_length: None,
            path: None,
        }
    );

    let value = processed_event.to_string().unwrap();
    assert_eq!(value, "{\"message\":\"Hello *****@*****.***.  You signed up with card ****-****-****-1234. Your home folder is C:\\\\Users\\\\[username] Look at our compliance Look at our compliance\",\"extra\":{\"bar\":true,\"foo\":null},\"ip\":null,\"metadata\":{\"extra\":{\"foo\":{\"\":{\"remarks\":[[[\"remove_foo\"]]]}}},\"ip\":{\"\":{\"remarks\":[[[\"remove_ip\",\"IP address removed\"]]]}},\"message\":{\"\":{\"original_length\":127,\"remarks\":[[[\"email_address\",\"potential email address\"],[6,21]],[[\"creditcard_number\",\"creditcard number\"],[81,100]],[[\"path_username\",\"username in path\"],[393,403]]]}}}}");
}
