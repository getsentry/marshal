//! PII stripping and normalization rule configuration.

use std::collections::BTreeMap;
use std::fmt;

use regex::{Regex, RegexBuilder};
use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer};

/// A regex pattern for text replacement.
pub struct Pattern(Regex);

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
    /// Truncates a string's tail.
    TruncateString {
        /// The maximum length of the string.
        max_length: u32,
    },
    /// Truncates a path in the middle.
    TruncatePath {
        /// Maximum length of the path.
        max_length: u32,
    },
    /// Truncates deep objects.
    DepthLimit {
        /// Maximum depth starting at the rule entry point.
        max_depth: u32,
    },
    /// Applies a regular expression.
    Pattern {
        /// The regular expression to apply.
        pattern: Pattern,
        /// The match group indices to replace.
        replace_groups: Option<Vec<u8>>,
    },
    /// Replaces the value for well-known keys in accociative
    RemovePairValue {
        /// A pattern to match for keys.
        key_pattern: Pattern,
    },
}

///
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
        new_value: String,
    },
}

/// A single rule configuration.
#[derive(Serialize, Deserialize, Debug)]
pub struct Rule {
    #[serde(flatten)]
    rule: RuleType,
    replace_with: Replacement,
    note: Option<String>,
}

/// A set of named rule configurations.
#[derive(Serialize, Deserialize, Debug)]
pub struct RuleConfig {
    rules: BTreeMap<String, Rule>,
    #[serde(default)]
    applications: BTreeMap<String, Vec<String>>,
}

#[test]
fn test_config() {
    use serde_json;
    let cfg: RuleConfig = serde_json::from_str(r#"{
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
            "freeform_text": ["path_username", "creditcard_numbers", "email_address", "ipv4"],
            "structured_data": ["path_username", "creditcard_numbers", "email_address", "ipv4", "password_pairs"]
        }
    }"#).unwrap();
    println!("{:#?}", &cfg);
}
