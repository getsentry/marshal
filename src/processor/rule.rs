//! PII stripping and normalization rule configuration.

use std::cmp;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use hmac::{Hmac, Mac};
use regex::{Regex, RegexBuilder};
use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer};
use serde_json;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use protocol::{Annotated, Meta, Remark, RemarkType, Value};

use super::builtin::BUILTIN_RULES;
use super::chunk::{self, Chunk};
use super::pii::{PiiKind, PiiProcessor, ProcessAnnotatedValue, ValueInfo};

lazy_static! {
    static ref NULL_SPLIT_RE: Regex = #[cfg_attr(feature = "cargo-clippy", allow(trivial_regex))]
    Regex::new("\x00").unwrap();
}

#[cfg_attr(rustfmt, rustfmt_skip)]
macro_rules! ip {
    (v4s) => { "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" };
    (v4a) => { concat!(ip!(v4s), "\\.", ip!(v4s), "\\.", ip!(v4s), "\\.", ip!(v4s)) };
    (v6s) => { "[0-9a-fA-F]{1,4}" };
}

#[cfg_attr(rustfmt, rustfmt_skip)]
lazy_static! {
    static ref GROUP_1: BTreeSet<u8> = {
        let mut set = BTreeSet::new();
        set.insert(1);
        set
    };
    static ref IMEI_REGEX: Regex = Regex::new(
        r#"(?x)
            \b
                (\d{2}-?
                 \d{6}-?
                 \d{6}-?
                 \d{1,2})
            \b
        "#
    ).unwrap();
    static ref MAC_REGEX: Regex = Regex::new(
        r#"(?x)
            \b([[:xdigit:]]{2}[:-]){5}[[:xdigit:]]{2}\b
        "#
    ).unwrap();
    static ref EMAIL_REGEX: Regex = Regex::new(
        r#"(?x)
            \b
                [a-zA-Z0-9.!\#$%&'*+/=?^_`{|}~-]+
                @
                [a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*
            \b
    "#
    ).unwrap();
    static ref IPV4_REGEX: Regex = Regex::new(concat!("\\b", ip!(v4a), "\\b")).unwrap();
    static ref IPV6_REGEX: Regex = Regex::new(
        concat!(
            "(?i)(?:[\\s]|[[:punct:]]|^)(",
                "(", ip!(v6s), ":){7}", ip!(v6s), "|",
                "(", ip!(v6s), ":){1,7}:|",
                "(", ip!(v6s), ":){1,6}::", ip!(v6s), "|",
                "(", ip!(v6s), ":){1,5}:(:", ip!(v6s), "){1,2}|",
                "(", ip!(v6s), ":){1,4}:(:", ip!(v6s), "){1,3}|",
                "(", ip!(v6s), ":){1,3}:(:", ip!(v6s), "){1,4}|",
                "(", ip!(v6s), ":){1,2}:(:", ip!(v6s), "){1,5}|",
                ip!(v6s), ":((:", ip!(v6s), "){1,6})|",
                ":((:", ip!(v6s), "){1,7}|:)|",
                "fe80:(:", ip!(v6s), "){0,4}%[0-9a-zA-Z]{1,}",
                "::(ffff(:0{1,4}){0,1}:){0,1}", ip!(v4a), "|",
                "(", ip!(v6s), ":){1,4}:", ip!(v4a),
            ")([\\s]|[[:punct:]]|$)",
        )
    ).unwrap();
    static ref CREDITCARD_REGEX: Regex = Regex::new(
        r#"(?x)
            \d{4}[- ]?\d{4,6}[- ]?\d{4,5}(?:[- ]?\d{4})
    "#
    ).unwrap();
    static ref PATH_REGEX: Regex = Regex::new(
        r#"(?ix)
            (?:
                (?:
                    \b(?:[a-zA-Z]:[\\/])?
                    (?:users|home|documents and settings|[^/\\]+[/\\]profiles)[\\/]
                ) | (?:
                    /(?:home|users)/
                )
            )
            (
                [^/\\]+
            )
        "#
    ).unwrap();
}

/// A regex pattern for text replacement.
#[derive(Clone)]
pub(crate) struct Pattern(pub Regex);

impl From<&'static str> for Pattern {
    fn from(pattern: &'static str) -> Pattern {
        Pattern(Regex::new(pattern).unwrap())
    }
}

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
#[derive(Serialize, Deserialize, Debug, Clone)]
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
    /// Matchse an IMEI or IMEISV
    Imei,
    /// Matches a mac address
    Mac,
    /// Matches an email
    Email,
    /// Matches any IP address
    Ip,
    /// Matches a creditcard number
    Creditcard,
    /// Sanitizes a path from user data
    Userpath,
    /// Unconditionally removes the value
    Remove,
    /// Applies multiple rules.
    Multiple {
        /// A reference to other rules to apply
        rules: Vec<String>,
        /// When set to true, the outer rule is reported.
        #[serde(default)]
        hide_rule: bool,
    },
    /// Applies another rule.  Works like a single multiple.
    Alias {
        /// A reference to another rule to apply.
        rule: String,
        /// When set to true, the outer rule is reported.
        #[serde(default)]
        hide_rule: bool,
    },
    /// When a regex matches a key, a value is removed
    #[serde(rename_all = "camelCase")]
    RedactPair {
        /// A pattern to match for keys.
        key_pattern: Pattern,
    },
}

/// Defines the hash algorithm to use for hashing
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "cargo-clippy", allow(enum_variant_names))]
pub(crate) enum HashAlgorithm {
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
    fn hash_value(self, text: &str, key: Option<&str>, config: &PiiConfig) -> String {
        let key = key.unwrap_or_else(|| {
            config
                .vars
                .hash_key
                .as_ref()
                .map(|x| x.as_str())
                .unwrap_or("")
        });
        macro_rules! hmac {
            ($ty:ident) => {{
                let mut mac = Hmac::<$ty>::new_varkey(key.as_bytes()).unwrap();
                mac.input(text.as_bytes());
                format!("{:X}", mac.result().code())
            }};
        }
        match self {
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
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "method", rename_all = "camelCase")]
pub(crate) enum Redaction {
    /// The default redaction for this operation (normally equivalen to `Remove`).
    ///
    /// The main difference to `Remove` is that if the redaction is explicitly
    /// set to `Remove` it also applies in situations where a default
    /// redaction is therwise not passed down (for instance with `Multiple`).
    Default,
    /// Removes the value and puts nothing in its place.
    Remove,
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

impl Default for Redaction {
    fn default() -> Redaction {
        Redaction::Default
    }
}

fn in_range(range: (Option<i32>, Option<i32>), pos: usize, len: usize) -> bool {
    fn get_range_index(idx: Option<i32>, len: usize, default: usize) -> usize {
        match idx {
            None => default,
            Some(idx) if idx < 0 => len.saturating_sub(-idx as usize),
            Some(idx) => cmp::min(idx as usize, len),
        }
    }

    let start = get_range_index(range.0, len, 0);
    let end = get_range_index(range.1, len, len);
    pos >= start && pos < end
}

fn apply_regex_to_chunks(
    redaction: &Redaction,
    chunks: Vec<Chunk>,
    meta: Meta,
    regex: &Regex,
    replace_groups: Option<&BTreeSet<u8>>,
    rule: &Rule,
    config: &PiiConfig,
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
                text: text[pos..piece.start()].to_string(),
            });
            rv.push(replacement_chunks.pop().unwrap());
            pos = piece.end();
        }
        rv.push(Chunk::Text {
            text: text[pos..].to_string(),
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
                            redaction.insert_replacement_chunks(rule, config, g.as_str(), &mut rv);
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
                redaction.insert_replacement_chunks(rule, config, g0.as_str(), &mut rv);
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

impl Redaction {
    fn insert_replacement_chunks(
        &self,
        rule: &Rule,
        config: &PiiConfig,
        text: &str,
        output: &mut Vec<Chunk>,
    ) {
        match *self {
            Redaction::Default | Redaction::Remove => {
                output.push(Chunk::Redaction {
                    rule_id: rule.rule_id().to_string(),
                    ty: RemarkType::Removed,
                    text: "".to_string(),
                });
            }
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
            Redaction::Hash {
                ref algorithm,
                ref key,
            } => {
                output.push(Chunk::Redaction {
                    ty: RemarkType::Pseudonymized,
                    rule_id: rule.rule_id().into(),
                    text: algorithm.hash_value(text, key.as_ref().map(|x| x.as_str()), config),
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

    fn replace_value(
        &self,
        rule: &Rule,
        config: &PiiConfig,
        mut annotated: Annotated<Value>,
    ) -> Annotated<Value> {
        match *self {
            Redaction::Default | Redaction::Remove => {
                annotated.with_removed_value(Remark::new(RemarkType::Removed, rule.rule_id()))
            }
            Redaction::Mask { .. } => match annotated {
                Annotated(Some(value), meta) => {
                    let value_as_string = value.to_string();
                    let original_length = value_as_string.len();
                    let mut output = vec![];
                    self.insert_replacement_chunks(
                        rule,
                        rule.config(),
                        &value_as_string,
                        &mut output,
                    );
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
            Redaction::Hash {
                ref algorithm,
                ref key,
            } => match annotated {
                Annotated(Some(value), mut meta) => {
                    let value_as_string = value.to_string();
                    let original_length = value_as_string.len();
                    let value = algorithm.hash_value(
                        &value_as_string,
                        key.as_ref().map(|x| x.as_str()),
                        config,
                    );
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
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RuleSpec {
    #[serde(flatten)]
    pub(crate) ty: RuleType,
    #[serde(default)]
    pub(crate) redaction: Redaction,
}

/// A rule is a rule config plus id.
#[derive(Debug, Clone)]
pub(crate) struct Rule<'a> {
    id: &'a str,
    spec: &'a RuleSpec,
    cfg: &'a PiiConfig,
}

/// Common config vars.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Vars {
    /// The default secret key for hashing operations.
    hash_key: Option<String>,
}

/// A set of named rule configurations.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct PiiConfig {
    #[serde(default)]
    pub(crate) rules: BTreeMap<String, RuleSpec>,
    #[serde(default)]
    pub(crate) vars: Vars,
    #[serde(default)]
    pub(crate) applications: BTreeMap<PiiKind, Vec<String>>,
}

/// A PII processor that uses JSON rules.
#[derive(Debug)]
pub struct RuleBasedPiiProcessor<'a> {
    cfg: &'a PiiConfig,
    applications: BTreeMap<PiiKind, Vec<Rule<'a>>>,
}

impl PiiConfig {
    /// Loads a PII config from a JSON string.
    pub fn from_json(s: &str) -> Result<PiiConfig, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Serializes an annotated value into a JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self)
    }

    /// Serializes an annotated value into a pretty JSON string.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self)
    }

    /// Creates a PII processor from the config.
    pub fn processor(&self) -> RuleBasedPiiProcessor {
        RuleBasedPiiProcessor::new(self)
    }

    /// Looks up a rule in the PII config.
    fn lookup_rule<'a>(&'a self, rule_id: &'a str) -> Option<Rule<'a>> {
        if let Some(rule_spec) = self.rules.get(rule_id) {
            Some(Rule {
                id: rule_id,
                spec: rule_spec,
                cfg: self,
            })
        } else if let Some(rule_spec) = BUILTIN_RULES.get(rule_id) {
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

    fn lookup_referenced_rule(
        &'a self,
        rule_id: &'a str,
        hide_rule: bool,
    ) -> Option<(Rule, Option<&'a Rule>, Option<&'a Redaction>)> {
        if let Some(rule) = self.config().lookup_rule(rule_id) {
            let report_rule = if hide_rule { Some(self) } else { None };
            let redaction_override = match self.spec.redaction {
                Redaction::Default => None,
                ref red => Some(red),
            };
            Some((rule, report_rule, redaction_override))
        } else {
            // XXX: handle bad references here?
            None
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
        report_rule: Option<&Rule>,
        redaction_override: Option<&Redaction>,
    ) -> Result<(Vec<Chunk>, Meta), (Vec<Chunk>, Meta)> {
        let report_rule = report_rule.unwrap_or(self);
        let redaction = redaction_override.unwrap_or(&self.spec.redaction);

        let mut rv = (chunks, meta);
        macro_rules! apply_regex {
            ($regex:expr, $replace_groups:expr) => {{
                rv = apply_regex_to_chunks(
                    redaction,
                    rv.0,
                    rv.1,
                    $regex,
                    $replace_groups,
                    report_rule,
                    self.cfg,
                );
            }};
        }

        match self.spec.ty {
            RuleType::Pattern {
                ref pattern,
                ref replace_groups,
            } => apply_regex!(&pattern.0, replace_groups.as_ref()),
            RuleType::Imei => apply_regex!(&IMEI_REGEX, None),
            RuleType::Mac => apply_regex!(&MAC_REGEX, None),
            RuleType::Email => apply_regex!(&EMAIL_REGEX, None),
            RuleType::Ip => {
                apply_regex!(&IPV4_REGEX, None);
                apply_regex!(&IPV6_REGEX, Some(&*GROUP_1));
            }
            RuleType::Creditcard => apply_regex!(&CREDITCARD_REGEX, None),
            RuleType::Userpath => apply_regex!(&PATH_REGEX, Some(&*GROUP_1)),
            RuleType::Alias {
                ref rule,
                hide_rule,
            } => {
                if let Some((rule, report_rule, redaction_override)) =
                    self.lookup_referenced_rule(rule, hide_rule)
                {
                    rv = rule.process_chunks(rv.0, rv.1, report_rule, redaction_override)?;
                }
            }
            RuleType::Multiple {
                ref rules,
                hide_rule,
            } => {
                for rule_id in rules.iter() {
                    if let Some((rule, report_rule, redaction_override)) =
                        self.lookup_referenced_rule(rule_id, hide_rule)
                    {
                        rv = match rule.process_chunks(rv.0, rv.1, report_rule, redaction_override)
                        {
                            Ok(rv) => rv,
                            Err(rv) => rv,
                        };
                    }
                }
            }
            // no special handling for strings, falls back to `process_value`
            RuleType::Remove | RuleType::RedactPair { .. } => return Err(rv),
        }

        Ok(rv)
    }

    /// Applies the rule to the given value.
    ///
    /// In case `Err` is returned the caller is expected to try the next rule.  If
    /// `Ok` is returned then no further modifications are applied.
    fn process_value(
        &self,
        mut value: Annotated<Value>,
        kind: PiiKind,
        report_rule: Option<&Rule>,
        redaction_override: Option<&Redaction>,
    ) -> Result<Annotated<Value>, Annotated<Value>> {
        let _kind = kind;
        let report_rule = report_rule.unwrap_or(self);
        let redaction = redaction_override.unwrap_or(&self.spec.redaction);

        match self.spec.ty {
            // pattern matches are not implemented for non strings
            RuleType::Pattern { .. }
            | RuleType::Imei
            | RuleType::Mac
            | RuleType::Email
            | RuleType::Ip
            | RuleType::Creditcard
            | RuleType::Userpath => Err(value),
            RuleType::Remove => Ok(redaction.replace_value(report_rule, self.config(), value)),
            RuleType::Alias {
                ref rule,
                hide_rule,
            } => {
                if let Some((rule, report_rule, redaction_override)) =
                    self.lookup_referenced_rule(rule, hide_rule)
                {
                    rule.process_value(value, kind, report_rule, redaction_override)
                } else {
                    Err(value)
                }
            }
            RuleType::Multiple {
                ref rules,
                hide_rule,
            } => {
                let mut processed = false;
                for rule_id in rules.iter() {
                    if let Some((rule, report_rule, redaction_override)) =
                        self.lookup_referenced_rule(rule_id, hide_rule)
                    {
                        value = match rule.process_value(
                            value,
                            kind,
                            report_rule,
                            redaction_override,
                        ) {
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
            RuleType::RedactPair { ref key_pattern } => {
                let mut should_redact = false;
                if let Some(path) = value.meta().path() {
                    if key_pattern.0.is_match(&path) {
                        should_redact = true;
                    }
                }
                if should_redact {
                    Ok(redaction.replace_value(report_rule, self.config(), value))
                } else {
                    Err(value)
                }
            }
        }
    }
}

impl<'a> RuleBasedPiiProcessor<'a> {
    /// Creates a new rule based PII processor from a config.
    fn new(cfg: &'a PiiConfig) -> RuleBasedPiiProcessor<'a> {
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

        RuleBasedPiiProcessor { cfg, applications }
    }

    /// Returns a reference to the config that created the processor.
    pub fn config(&self) -> &PiiConfig {
        self.cfg
    }

    /// Processes a root value (annotated event for instance)
    ///
    /// This is a convenience method that invokes `ProcessAnnotatedValue`
    /// with some sensible defaults.
    pub fn process_root_value<T: ProcessAnnotatedValue>(
        &self,
        value: Annotated<T>,
    ) -> Annotated<T> {
        ProcessAnnotatedValue::process_annotated_value(value, self, &ValueInfo::default())
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
                rv = match rule.process_chunks(rv.0, rv.1, None, None) {
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
                value = match rule.process_value(value, kind, None, None) {
                    Ok(value) => return value,
                    Err(value) => value,
                };
            }
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::Map;

    #[test]
    fn test_basic_stripping() {
        let cfg = PiiConfig::from_json(
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
                "type": "redactPair",
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

        let event = Annotated::<Event>::from_json(r#"
        {
            "message": "Hello peter@gmail.com.  You signed up with card 1234-1234-1234-1234. Your home folder is C:\\Users\\peter. Look at our compliance from 127.0.0.1",
            "extra": {
                "foo": 42,
                "bar": true
            },
            "ip": "192.168.1.1"
        }
    "#).unwrap();

        let processor = cfg.processor();
        let processed_event = processor.process_root_value(event);
        let new_event = processed_event.clone().0.unwrap();

        let message = new_event.message.value().unwrap();
        println!("{:#?}", &new_event);
        assert_eq_str!(
            message,
            "Hello *****@*****.***.  You signed up with card ****-****-****-1234. \
             Your home folder is C:\\Users\\[username] Look at our compliance \
             from 5A2DF387CD660E9F3E0AB20F9E7805450D56C5DACE9B959FC620C336E2B5D09A"
        );
        assert_eq_dbg!(
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

        let annotated = new_event.extra.value().unwrap().get("foo").unwrap();
        assert!(annotated.value().is_none());
        assert_eq_dbg!(
            annotated.meta(),
            &Meta {
                remarks: vec![Remark::new(RemarkType::Removed, "remove_foo")],
                errors: vec![],
                original_length: None,
                path: None,
            }
        );

        let ip = &new_event.ip;
        assert!(ip.value().is_none());
        assert_eq_dbg!(
            ip.meta(),
            &Meta {
                remarks: vec![Remark::new(RemarkType::Removed, "remove_ip")],
                errors: vec![],
                original_length: None,
                path: None,
            }
        );

        let value = processed_event.to_json_pretty().unwrap();
        assert_eq_str!(value, r#"{
  "message": "Hello *****@*****.***.  You signed up with card ****-****-****-1234. Your home folder is C:\\Users\\[username] Look at our compliance from 5A2DF387CD660E9F3E0AB20F9E7805450D56C5DACE9B959FC620C336E2B5D09A",
  "extra": {
    "bar": true,
    "foo": null
  },
  "ip": null,
  "_meta": {
    "extra": {
      "foo": {
        "": {
          "rem": [
            [
              "remove_foo",
              "x"
            ]
          ]
        }
      }
    },
    "ip": {
      "": {
        "rem": [
          [
            "remove_ip",
            "x"
          ]
        ]
      }
    },
    "message": {
      "": {
        "len": 142,
        "rem": [
          [
            "email_address",
            "m",
            6,
            21
          ],
          [
            "creditcard_number",
            "m",
            48,
            67
          ],
          [
            "path_username",
            "s",
            98,
            108
          ],
          [
            "hash_ip",
            "p",
            137,
            201
          ]
        ]
      }
    }
  }
}"#);
    }

    #[test]
    fn test_well_known_stripping() {
        let cfg = PiiConfig::from_json(
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

        let event = Annotated::<Event>::from_json(
            r#"{
            "message": "u/f444e9498e6b on d/db3d6129ca10 (144.132.11.23): Hello World!"
        }"#,
        ).unwrap();

        let processor = cfg.processor();
        let processed_event = processor.process_root_value(event);
        let new_event = processed_event.clone().0.unwrap();

        let message = new_event.message.value().unwrap();
        println!("{:#?}", &new_event);
        assert_eq_str!(message, "[user-id] on [device-id] ([ip]): Hello World!");
        assert_eq_dbg!(
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

        let value = processed_event.to_json_pretty().unwrap();
        assert_eq_str!(
            value,
            r#"{
  "message": "[user-id] on [device-id] ([ip]): Hello World!",
  "_meta": {
    "message": {
      "": {
        "len": 62,
        "rem": [
          [
            "user_id",
            "s",
            0,
            9
          ],
          [
            "device_id",
            "s",
            13,
            24
          ],
          [
            "@ip:replace",
            "s",
            26,
            30
          ]
        ]
      }
    }
  }
}"#
        );
    }

    #[test]
    fn test_well_known_stripping_common_redaction() {
        let cfg = PiiConfig::from_json(
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
                "hide_rule": true,
                "redaction": {
                    "method": "replace",
                    "text": "[id]"
                },
                "rules": [
                    "user_id",
                    "device_id",
                    "@ip:replace"
                ]
            }
        },
        "applications": {
            "freeform": ["ids"]
        }
    }"#,
        ).unwrap();

        #[derive(ProcessAnnotatedValue, Debug, Deserialize, Serialize, Clone)]
        struct Event {
            #[process_annotated_value(pii_kind = "freeform")]
            message: Annotated<String>,
        }

        let event = Annotated::<Event>::from_json(
            r#"
        {
            "message": "u/f444e9498e6b on d/db3d6129ca10 (144.132.11.23): Hello World!"
        }
    "#,
        ).unwrap();

        let processor = cfg.processor();
        let processed_event = processor.process_root_value(event);
        let new_event = processed_event.clone().0.unwrap();

        let message = new_event.message.value().unwrap();
        println!("{:#?}", &new_event);
        assert_eq_str!(message, "[id] on [id] ([id]): Hello World!");
        assert_eq_dbg!(
            new_event.message.meta(),
            &Meta {
                remarks: vec![
                    Remark::with_range(RemarkType::Substituted, "ids", (0, 4)),
                    Remark::with_range(RemarkType::Substituted, "ids", (8, 12)),
                    Remark::with_range(RemarkType::Substituted, "ids", (14, 18)),
                ],
                errors: vec![],
                original_length: Some(62),
                path: None,
            }
        );

        let value = processed_event.to_json_pretty().unwrap();
        assert_eq_str!(
            value,
            r#"{
  "message": "[id] on [id] ([id]): Hello World!",
  "_meta": {
    "message": {
      "": {
        "len": 62,
        "rem": [
          [
            "ids",
            "s",
            0,
            4
          ],
          [
            "ids",
            "s",
            8,
            12
          ],
          [
            "ids",
            "s",
            14,
            18
          ]
        ]
      }
    }
  }
}"#
        );
    }

    #[test]
    fn test_rules_precedence() {
        fn inner(cfg: &PiiConfig) {
            #[derive(ProcessAnnotatedValue, Debug, Deserialize, Serialize, Clone)]
            struct Event {
                #[process_annotated_value(pii_kind = "databag")]
                extra: Annotated<Map<Value>>,
            }

            let event = Annotated::<Event>::from_json(
                r#"{"extra": {"foo": "Paid with card 1234-1234-1234-1234 on d/deadbeef1234"}}"#,
            ).unwrap();

            let processor = cfg.processor();
            let processed_event = processor.process_root_value(event);

            assert_eq_str!(
                processed_event.to_json().unwrap(),
                r#"{"extra":{"foo":null},"_meta":{"extra":{"foo":{"":{"rem":[["remove_all_message_keys","x"]]}}}}}"#
            );
        }

        inner(
            &PiiConfig::from_json(
                r#"{
          "applications": {
            "databag": [
              "remove_all_message_keys",
              "@mac:hash"
            ]
          },
          "rules": {
            "remove_all_message_keys": {
              "keyPattern": "foo",
              "type": "redactPair"
            }
          }
        }"#,
            ).unwrap(),
        );

        inner(
            &PiiConfig::from_json(
                r#"{
          "applications": {
            "databag": [
              "@mac:hash",
              "remove_all_message_keys"
            ]
          },
          "rules": {
            "remove_all_message_keys": {
              "keyPattern": "foo",
              "type": "redactPair"
            }
          }
        }"#,
            ).unwrap(),
        );
    }
}
