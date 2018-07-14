//! PII stripping and normalization rule configuration.

use std::cmp;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use hmac::{Hmac, Mac};
use regex::{Regex, RegexBuilder};
use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use chunk::{self, Chunk};
use common::Value;
use detectors;
use meta::{Annotated, Meta, Remark, RemarkType};
use processor::{PiiKind, PiiProcessor, ProcessAnnotatedValue, ValueInfo};

lazy_static! {
    static ref NULL_SPLIT_RE: Regex = Regex::new("\x00").unwrap();
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
#[serde(tag = "type", rename_all = "camelCase")]
pub(crate) enum RuleType {
    /// Applies a regular expression.
    #[serde(rename_all = "camelCase")]
    Pattern {
        /// The regular expression to apply.
        pattern: Pattern,
        /// The match group indices to replace.
        replace_groups: Option<BTreeSet<u8>>,
    },
    /// Matches an email
    Email,
    /// Matches any IP address
    Ip,
    /// Matches a creditcard number
    Creditcard,
    /// Unconditionally removes the value
    Remove,
    /// Applies multiple rules.
    Multiple { rules: Vec<String> },
    /// When a regex matches a key, a value is removed
    #[serde(rename_all = "camelCase")]
    RemovePair {
        /// A pattern to match for keys.
        key_pattern: Pattern,
    },
}

/// Defines the hash algorithm to use for hashing
#[derive(Serialize, Deserialize, Debug)]
pub enum HashAlgorithm {
    /// HMAC-SHA1
    #[serde(rename = "HMAC-SHA1")]
    HmacSha1,
    /// HMAC-SHA256
    #[serde(rename = "HMAC-SHA256")]
    HmacSha256,
    /// HMAC-SHA512
    #[serde(rename = "HMAC-SHA512")]
    HmacSha512,
}

impl Default for HashAlgorithm {
    fn default() -> HashAlgorithm {
        HashAlgorithm::HmacSha1
    }
}

impl HashAlgorithm {
    fn hash_value(&self, text: &str, key: &str) -> String {
        macro_rules! hmac {
            ($ty:ident) => {{
                let mut mac = Hmac::<$ty>::new_varkey(key.as_bytes()).unwrap();
                mac.input(text.as_bytes());
                format!("{:X}", mac.result().code())
            }};
        }
        match *self {
            HashAlgorithm::HmacSha1 => hmac!(Sha1),
            HashAlgorithm::HmacSha256 => hmac!(Sha256),
            HashAlgorithm::HmacSha512 => hmac!(Sha512),
        }
    }
}

fn default_mask_char() -> char {
    '*'
}

/// Defines how replacements happen.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "method", rename_all = "camelCase")]
pub(crate) enum Redaction {
    /// Replaces the matched group with a new value.
    #[serde(rename_all = "camelCase")]
    Replace {
        /// The replacement string.
        text: String,
    },
    /// Overwrites the matched value by masking.
    #[serde(rename_all = "camelCase")]
    Mask {
        /// The character to mask with.
        #[serde(default = "default_mask_char")]
        mask_char: char,
        /// Characters to skip during masking to preserve structure.
        #[serde(default)]
        chars_to_ignore: String,
        /// Index range to mask in. Negative indices count from the string's end.
        #[serde(default)]
        range: (Option<i32>, Option<i32>),
    },
    /// Replaces the value with a hash
    #[serde(rename_all = "camelCase")]
    Hash {
        /// The hash algorithm
        #[serde(default)]
        algorithm: HashAlgorithm,
        /// The secret key (if not to use the default)
        key: Option<String>,
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

impl Redaction {
    fn insert_replacement_chunks(&self, rule: &Rule, text: &str, output: &mut Vec<Chunk>) {
        match *self {
            Redaction::Mask {
                mask_char,
                ref chars_to_ignore,
                range,
            } => {
                let chars_to_ignore: BTreeSet<char> = chars_to_ignore.chars().collect();
                let mut buf = Vec::with_capacity(text.len());

                for (idx, c) in text.chars().enumerate() {
                    if in_range(range, idx, text.len()) && !chars_to_ignore.contains(&c) {
                        buf.push(mask_char);
                    } else {
                        buf.push(c);
                    }
                }
                output.push(Chunk::Redaction {
                    ty: RemarkType::Masked,
                    rule_id: rule.rule_id().into(),
                    text: buf.into_iter().collect(),
                })
            }
            Redaction::Hash { ref algorithm, .. } => {
                output.push(Chunk::Redaction {
                    ty: RemarkType::Pseudonymized,
                    rule_id: rule.rule_id().into(),
                    text: algorithm.hash_value(text, rule.hash_key()),
                });
            }
            Redaction::Replace { ref text } => {
                output.push(Chunk::Redaction {
                    ty: RemarkType::Substituted,
                    rule_id: rule.rule_id().into(),
                    text: text.clone(),
                });
            }
        }
    }

    fn set_replacement_value(
        &self,
        rule: &Rule,
        mut annotated: Annotated<Value>,
    ) -> Annotated<Value> {
        match *self {
            Redaction::Mask { .. } => match annotated {
                Annotated(Some(value), meta) => {
                    let value_as_string = value.to_string();
                    let original_length = value_as_string.len();
                    let mut output = vec![];
                    self.insert_replacement_chunks(rule, &value_as_string, &mut output);
                    let (value, mut meta) = chunk::chunks_to_string(output, meta);
                    if value.len() != original_length && meta.original_length.is_none() {
                        meta.original_length = Some(original_length as u32);
                    }
                    Annotated(Some(Value::String(value)), meta)
                }
                annotated @ Annotated(None, _) => {
                    annotated.with_removed_value(Remark::new(RemarkType::Masked, rule.rule_id()))
                }
            },
            Redaction::Hash { ref algorithm, .. } => match annotated {
                Annotated(Some(value), mut meta) => {
                    let value_as_string = value.to_string();
                    let original_length = value_as_string.len();
                    let value = algorithm.hash_value(&value_as_string, rule.hash_key());
                    if value.len() != original_length && meta.original_length.is_none() {
                        meta.original_length = Some(original_length as u32);
                    }
                    Annotated(Some(Value::String(value)), meta)
                }
                annotated @ Annotated(None, _) => annotated
                    .with_removed_value(Remark::new(RemarkType::Pseudonymized, rule.rule_id())),
            },
            Redaction::Replace { ref text } => {
                annotated.set_value(Some(Value::String(text.clone())));
                annotated
                    .meta_mut()
                    .remarks_mut()
                    .push(Remark::new(RemarkType::Substituted, rule.rule_id()));
                annotated
            }
        }
    }
}

/// A single rule configuration.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RuleSpec {
    #[serde(flatten)]
    pub(crate) ty: RuleType,
    pub(crate) redaction: Option<Redaction>,
}

/// A rule is a rule config plus id.
#[derive(Debug, Clone)]
pub(crate) struct Rule<'a> {
    id: &'a str,
    spec: &'a RuleSpec,
    cfg: &'a PiiConfig,
}

/// Common config vars.
#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Vars {
    /// The default secret key for hashing operations.
    hash_key: Option<String>,
}

/// A set of named rule configurations.
#[derive(Serialize, Deserialize, Debug)]
pub struct PiiConfig {
    rules: BTreeMap<String, RuleSpec>,
    #[serde(default)]
    vars: Vars,
    #[serde(default)]
    applications: BTreeMap<PiiKind, Vec<String>>,
}

/// A PII processor that uses JSON rules.
pub struct RuleBasedPiiProcessor<'a> {
    cfg: &'a PiiConfig,
    applications: BTreeMap<PiiKind, Vec<Rule<'a>>>,
}

impl PiiConfig {
    /// Looks up a rule in the PII config.
    fn lookup_rule<'a>(&'a self, rule_id: &'a str) -> Option<Rule<'a>> {
        if let Some(rule_spec) = self.rules.get(rule_id) {
            Some(Rule {
                id: rule_id,
                spec: rule_spec,
                cfg: self,
            })
        } else if let Some(rule_spec) = WELL_KNOWN_RULES.get(rule_id) {
            Some(Rule {
                id: rule_id,
                spec: rule_spec,
                cfg: self,
            })
        } else {
            None
        }
    }
}

impl<'a> Rule<'a> {
    /// The rule ID.
    pub fn rule_id(&self) -> &str {
        &self.id
    }

    /// Return a reference to the rule config.
    pub fn config(&self) -> &PiiConfig {
        self.cfg
    }

    /// Returns the hmac config key.
    pub fn hash_key(&self) -> &str {
        if let Some(Redaction::Hash {
            key: Some(ref key), ..
        }) = self.spec.redaction
        {
            key.as_str()
        } else if let Some(ref key) = self.config().vars.hash_key {
            key.as_str()
        } else {
            ""
        }
    }

    /// Inserts replacement chunks into the given chunk buffer.
    ///
    /// If the rule is configured with `redaction` then replacement chunks are
    /// added to the buffer based on that information.  If `redaction` is not
    /// defined an empty redaction chunk is added with the supplied note.
    fn insert_replacement_chunks(&self, text: &str, output: &mut Vec<Chunk>) {
        if let Some(ref redaction) = self.spec.redaction {
            redaction.insert_replacement_chunks(self, text, output);
        } else {
            output.push(Chunk::Redaction {
                rule_id: self.rule_id().to_string(),
                ty: RemarkType::Removed,
                text: "".to_string(),
            });
        }
    }

    /// Produces a new annotated value with replacement data.
    ///
    /// This fully replaces the value in the annotated value with the replacement value
    /// from the config.  If no replacement value is defined (which is likely) then
    /// then no value is set (null).  In either case the given note is recorded.
    fn replace_value(&self, annotated: Annotated<Value>) -> Annotated<Value> {
        if let Some(ref redaction) = self.spec.redaction {
            redaction.set_replacement_value(self, annotated)
        } else {
            annotated.with_removed_value(Remark::new(RemarkType::Removed, self.id))
        }
    }

    /// Processes the given chunks according to the rule.
    ///
    /// This works the same as `pii_process_chunks` in behavior.  This means that if an
    /// error is returned the caller falls back to regular value processing.
    fn process_chunks(
        &self,
        chunks: Vec<Chunk>,
        meta: Meta,
    ) -> Result<(Vec<Chunk>, Meta), (Vec<Chunk>, Meta)> {
        match self.spec.ty {
            RuleType::Pattern {
                ref pattern,
                ref replace_groups,
            } => Ok(self.apply_regex_to_chunks(chunks, meta, &pattern.0, replace_groups.as_ref())),
            RuleType::Email => {
                Ok(self.apply_regex_to_chunks(chunks, meta, &*detectors::EMAIL_REGEX, None))
            }
            RuleType::Ip => {
                let (chunks, meta) =
                    self.apply_regex_to_chunks(chunks, meta, &*detectors::IPV4_REGEX, None);
                let (chunks, meta) =
                    self.apply_regex_to_chunks(chunks, meta, &*detectors::IPV6_REGEX, None);
                Ok((chunks, meta))
            }
            RuleType::Creditcard => {
                Ok(self.apply_regex_to_chunks(chunks, meta, &*detectors::CREDITCARD_REGEX, None))
            }
            RuleType::Multiple { ref rules } => {
                let mut item = (chunks, meta);
                let mut processed = false;
                for rule_id in rules.iter() {
                    // XXX: log bad rule reference here
                    if let Some(rule) = self.config().lookup_rule(rule_id) {
                        item = match rule.process_chunks(item.0, item.1) {
                            Ok(rv) => {
                                processed = true;
                                rv
                            }
                            Err(rv) => rv,
                        };
                    }
                }
                if processed {
                    Ok(item)
                } else {
                    Err(item)
                }
            }
            // no special handling for strings, falls back to `process_value`
            RuleType::Remove | RuleType::RemovePair { .. } => Err((chunks, meta)),
        }
    }

    /// Applies a regex to chunks and meta.
    fn apply_regex_to_chunks(
        &self,
        chunks: Vec<Chunk>,
        meta: Meta,
        regex: &Regex,
        replace_groups: Option<&BTreeSet<u8>>,
    ) -> (Vec<Chunk>, Meta) {
        let mut search_string = String::new();
        let mut replacement_chunks = vec![];
        for chunk in chunks {
            match chunk {
                Chunk::Text { ref text } => search_string.push_str(&text.replace("\x00", "")),
                chunk @ Chunk::Redaction { .. } => {
                    replacement_chunks.push(chunk);
                    search_string.push('\x00');
                }
            }
        }
        replacement_chunks.reverse();
        let mut rv: Vec<Chunk> = vec![];

        fn process_text(text: &str, rv: &mut Vec<Chunk>, replacement_chunks: &mut Vec<Chunk>) {
            if text.is_empty() {
                return;
            }
            let mut pos = 0;
            for piece in NULL_SPLIT_RE.find_iter(text) {
                rv.push(Chunk::Text {
                    text: text[pos..piece.start()].to_string().into(),
                });
                rv.push(replacement_chunks.pop().unwrap());
                pos = piece.end();
            }
            rv.push(Chunk::Text {
                text: text[pos..].to_string().into(),
            });
        }

        let mut pos = 0;
        for m in regex.captures_iter(&search_string) {
            let g0 = m.get(0).unwrap();

            match replace_groups {
                Some(groups) => {
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
                                self.insert_replacement_chunks(g.as_str(), &mut rv);
                                pos = g.end();
                            }
                        }
                    }
                }
                None => {
                    process_text(
                        &search_string[pos..g0.start()],
                        &mut rv,
                        &mut replacement_chunks,
                    );
                    self.insert_replacement_chunks(g0.as_str(), &mut rv);
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

        (rv, meta)
    }

    /// Applies the rule to the given value.
    ///
    /// In case `Err` is returned the caller is expected to try the next rule.  If
    /// `Ok` is returned then no further modifications are applied.
    fn process_value(
        &self,
        mut value: Annotated<Value>,
        kind: PiiKind,
    ) -> Result<Annotated<Value>, Annotated<Value>> {
        let _kind = kind;
        match self.spec.ty {
            // pattern matches are not implemented for non strings
            RuleType::Pattern { .. } | RuleType::Email | RuleType::Ip | RuleType::Creditcard => {
                Err(value)
            }
            RuleType::Remove => {
                return Ok(self.replace_value(value));
            }
            RuleType::Multiple { ref rules } => {
                let mut processed = false;
                for rule_id in rules.iter() {
                    // XXX: handle bad references here?
                    if let Some(rule) = self.config().lookup_rule(rule_id) {
                        value = match rule.process_value(value, kind) {
                            Ok(rv) => {
                                processed = true;
                                rv
                            }
                            Err(rv) => rv,
                        };
                    }
                }
                if processed {
                    Ok(value)
                } else {
                    Err(value)
                }
            }
            RuleType::RemovePair { ref key_pattern } => {
                if let Some(ref path) = value.meta().path() {
                    if key_pattern.0.is_match(&path.to_string()) {
                        return Ok(self.replace_value(value));
                    }
                }
                Err(value)
            }
        }
    }
}

impl<'a> RuleBasedPiiProcessor<'a> {
    /// Creates a new rule based PII processor from a config.
    pub fn new(cfg: &'a PiiConfig) -> RuleBasedPiiProcessor<'a> {
        let mut applications = BTreeMap::new();

        for (&pii_kind, cfg_applications) in &cfg.applications {
            let mut rules = vec![];
            for application in cfg_applications {
                // XXX: log bad rule reference here
                if let Some(rule) = cfg.lookup_rule(application.as_str()) {
                    rules.push(rule);
                }
            }
            applications.insert(pii_kind, rules);
        }

        RuleBasedPiiProcessor {
            cfg: cfg,
            applications: applications,
        }
    }

    /// Returns a reference to the config that created the processor.
    pub fn config(&self) -> &PiiConfig {
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
            for rule in rules {
                rv = match rule.process_chunks(rv.0, rv.1) {
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
            for rule in rules {
                value = match rule.process_value(value, kind) {
                    Ok(value) => return value,
                    Err(value) => value,
                };
            }
        }
        value
    }
}

macro_rules! declare_well_known_rules {
    ($($rule_id:expr => $spec:expr;)*) => {
        lazy_static! {
            static ref WELL_KNOWN_RULES: BTreeMap<&'static str, &'static RuleSpec> = {
                let mut map = BTreeMap::new();
                $(
                    map.insert($rule_id, Box::leak(Box::new($spec)) as &'static _);
                )*
                map
            };
        }
    }
}

declare_well_known_rules! {
    "@ip:mask" => RuleSpec {
        ty: RuleType::Ip,
        redaction: Some(Redaction::Mask {
            mask_char: '*',
            chars_to_ignore: ".:".into(),
            range: (None, None),
        }),
    };

    "@ip:replace" => RuleSpec {
        ty: RuleType::Ip,
        redaction: Some(Redaction::Replace {
            text: "[ip]".into(),
        }),
    };

    "@ip:hash" => RuleSpec {
        ty: RuleType::Ip,
        redaction: Some(Redaction::Hash {
            algorithm: HashAlgorithm::HmacSha1,
            key: None,
        }),
    };

    "@email:mask" => RuleSpec {
        ty: RuleType::Email,
        redaction: Some(Redaction::Mask {
            mask_char: '*',
            chars_to_ignore: ".@".into(),
            range: (None, None),
        }),
    };

    "@email:replace" => RuleSpec {
        ty: RuleType::Email,
        redaction: Some(Redaction::Replace {
            text: "[email]".into(),
        }),
    };

    "@email:hash" => RuleSpec {
        ty: RuleType::Email,
        redaction: Some(Redaction::Hash {
            algorithm: HashAlgorithm::HmacSha1,
            key: None,
        }),
    };

    "@creditcard:mask" => RuleSpec {
        ty: RuleType::Creditcard,
        redaction: Some(Redaction::Mask {
            mask_char: '*',
            chars_to_ignore: " -".into(),
            range: (None, Some(-4)),
        }),
    };

    "@creditcard:replace" => RuleSpec {
        ty: RuleType::Creditcard,
        redaction: Some(Redaction::Replace {
            text: "[creditcard]".into(),
        }),
    };

    "@creditcard:hash" => RuleSpec {
        ty: RuleType::Creditcard,
        redaction: Some(Redaction::Hash {
            algorithm: HashAlgorithm::HmacSha1,
            key: None,
        }),
    };
}

#[test]
fn test_basic_stripping() {
    use common::Map;
    use meta::Remark;
    use serde_json;

    let cfg: PiiConfig = serde_json::from_str(
        r#"{
        "rules": {
            "path_username": {
                "type": "pattern",
                "pattern": "(?i)(?:\b[a-zA-Z]:)?(?:[/\\\\](?:users|home)[/\\\\])([^/\\\\\\s]+)",
                "replaceGroups": [1],
                "redaction": {
                    "method": "replace",
                    "text": "[username]"
                }
            },
            "creditcard_number": {
                "type": "pattern",
                "pattern": "\\d{4}[- ]?\\d{4,6}[- ]?\\d{4,5}(?:[- ]?\\d{4})",
                "redaction": {
                    "method": "mask",
                    "maskChar": "*",
                    "charsToIgnore": "- ",
                    "range": [0, -4]
                }
            },
            "email_address": {
                "type": "pattern",
                "pattern": "[a-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9-]+(\\.[a-z0-9-]+)*",
                "redaction": {
                    "method": "mask",
                    "maskChar": "*",
                    "charsToIgnore": "@."
                }
            },
            "remove_foo": {
                "type": "removePair",
                "keyPattern": "foo"
            },
            "remove_ip": {
                "type": "remove"
            },
            "hash_ip": {
                "type": "pattern",
                "pattern": "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
                "redaction": {
                    "method": "hash",
                    "algorithm": "HMAC-SHA256",
                    "key": "DEADBEEF1234"
                }
            }
        },
        "applications": {
            "freeform": ["path_username", "creditcard_number", "email_address", "hash_ip"],
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
            "message": "Hello peter@gmail.com.  You signed up with card 1234-1234-1234-1234. Your home folder is C:\\Users\\peter. Look at our compliance from 127.0.0.1",
            "extra": {
                "foo": 42,
                "bar": true
            },
            "ip": "192.168.1.1"
        }
    "#).unwrap();

    let processor = RuleBasedPiiProcessor::new(&cfg);
    let processed_event = processor.process_root_value(event);
    let new_event = processed_event.clone().0.unwrap();

    let message = new_event.message.value().unwrap();
    println!("{:#?}", &new_event);
    assert_eq!(
        message,
        "Hello *****@*****.***.  You signed up with card ****-****-****-1234. \
         Your home folder is C:\\Users\\[username] Look at our compliance \
         from 5A2DF387CD660E9F3E0AB20F9E7805450D56C5DACE9B959FC620C336E2B5D09A"
    );
    assert_eq!(
        new_event.message.meta(),
        &Meta {
            remarks: vec![
                Remark::with_range(RemarkType::Masked, "email_address", (6, 21)),
                Remark::with_range(RemarkType::Masked, "creditcard_number", (48, 67)),
                Remark::with_range(RemarkType::Substituted, "path_username", (98, 108)),
                Remark::with_range(RemarkType::Pseudonymized, "hash_ip", (137, 201)),
            ],
            errors: vec![],
            original_length: Some(142),
            path: None,
        }
    );

    let foo = new_event.extra.value().unwrap().get("foo").unwrap();
    assert!(foo.value().is_none());
    assert_eq!(
        foo.meta(),
        &Meta {
            remarks: vec![Remark::new(RemarkType::Removed, "remove_foo")],
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
            remarks: vec![Remark::new(RemarkType::Removed, "remove_ip")],
            errors: vec![],
            original_length: None,
            path: None,
        }
    );

    let value = processed_event.to_string().unwrap();
    assert_eq!(value, "{\"message\":\"Hello *****@*****.***.  You signed up with card ****-****-****-1234. Your home folder is C:\\\\Users\\\\[username] Look at our compliance from 5A2DF387CD660E9F3E0AB20F9E7805450D56C5DACE9B959FC620C336E2B5D09A\",\"extra\":{\"bar\":true,\"foo\":null},\"ip\":null,\"\":{\"extra\":{\"foo\":{\"\":{\"rem\":[[\"remove_foo\",\"x\"]]}}},\"ip\":{\"\":{\"rem\":[[\"remove_ip\",\"x\"]]}},\"message\":{\"\":{\"len\":142,\"rem\":[[\"email_address\",\"m\",6,21],[\"creditcard_number\",\"m\",48,67],[\"path_username\",\"s\",98,108],[\"hash_ip\",\"p\",137,201]]}}}}");
}

#[test]
fn test_well_known_stripping() {
    use meta::Remark;
    use serde_json;

    let cfg: PiiConfig = serde_json::from_str(
        r#"{
        "rules": {
            "user_id": {
                "type": "pattern",
                "pattern": "u/[a-f0-9]{12}",
                "redaction": {
                    "method": "replace",
                    "text": "[user-id]"
                }
            },
            "device_id": {
                "type": "pattern",
                "pattern": "d/[a-f0-9]{12}",
                "redaction": {
                    "method": "replace",
                    "text": "[device-id]"
                }
            },
            "ids": {
                "type": "multiple",
                "rules": [
                    "user_id",
                    "device_id"
                ]
            }
        },
        "applications": {
            "freeform": ["ids", "@ip:replace"]
        }
    }"#,
    ).unwrap();

    #[derive(ProcessAnnotatedValue, Debug, Deserialize, Serialize, Clone)]
    struct Event {
        #[process_annotated_value(pii_kind = "freeform")]
        message: Annotated<String>,
    }

    let event = Annotated::<Event>::from_str(
        r#"
        {
            "message": "u/f444e9498e6b on d/db3d6129ca10 (144.132.11.23): Hello World!"
        }
    "#,
    ).unwrap();

    let processor = RuleBasedPiiProcessor::new(&cfg);
    let processed_event = processor.process_root_value(event);
    let new_event = processed_event.clone().0.unwrap();

    let message = new_event.message.value().unwrap();
    println!("{:#?}", &new_event);
    assert_eq!(message, "[user-id] on [device-id] ([ip]): Hello World!");
    assert_eq!(
        new_event.message.meta(),
        &Meta {
            remarks: vec![
                Remark::with_range(RemarkType::Substituted, "user_id", (0, 9)),
                Remark::with_range(RemarkType::Substituted, "device_id", (13, 24)),
                Remark::with_range(RemarkType::Substituted, "@ip:replace", (26, 30)),
            ],
            errors: vec![],
            original_length: Some(62),
            path: None,
        }
    );

    let value = processed_event.to_string().unwrap();
    assert_eq!(value, "{\"message\":\"[user-id] on [device-id] ([ip]): Hello World!\",\"\":{\"message\":{\"\":{\"len\":62,\"rem\":[[\"user_id\",\"s\",0,9],[\"device_id\",\"s\",13,24],[\"@ip:replace\",\"s\",26,30]]}}}}");
}
