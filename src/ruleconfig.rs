use std::collections::BTreeMap;
use std::fmt;

use regex::{Regex, RegexBuilder};
use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer};

pub struct Pattern(Regex);

impl fmt::Debug for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl Serialize for Pattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Pattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: String = String::deserialize(deserializer)?
            .parse()
            .map_err(Error::custom)?;
        let pattern = RegexBuilder::new(&raw)
            .size_limit(262_144)
            .build()
            .map_err(Error::custom)?;
        Ok(Pattern(pattern))
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleType {
    TruncateString {
        max_length: u32,
    },
    TruncatePath {
        max_length: u32,
    },
    DepthLimit {
        max_depth: u32,
    },
    Pattern {
        pattern: Pattern,
        replace_groups: Option<Vec<u8>>,
    },
    RemovePairValue {
        key_pattern: Pattern,
    },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged, rename_all = "snake_case")]
pub enum Replacement {
    Mask {
        mask_with_char: char,
        #[serde(default)]
        chars_to_ignore: String,
        #[serde(default)]
        mask_range: (Option<i32>, Option<i32>),
    },
    NewValue {
        new_value: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Rule {
    #[serde(flatten)]
    rule: RuleType,
    replace_with: Replacement,
    note: Option<String>,
}

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
    //panic!();
}
