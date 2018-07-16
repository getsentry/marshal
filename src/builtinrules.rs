use std::collections::BTreeMap;

use rule::{HashAlgorithm, Redaction, RuleSpec, RuleType};

macro_rules! declare_builtin_rules {
    ($($rule_id:expr => $spec:expr;)*) => {
        lazy_static! {
            pub(crate) static ref BUILTIN_RULES: BTreeMap<&'static str, &'static RuleSpec> = {
                let mut map = BTreeMap::new();
                $(
                    map.insert($rule_id, Box::leak(Box::new($spec)) as &'static _);
                )*
                map
            };
        }
    }
}

macro_rules! rule_alias {
    ($target:expr) => {
        RuleSpec {
            ty: RuleType::Alias {
                rule: ($target).into(),
                hide_rule: false,
            },
            redaction: Redaction::Default,
        }
    };
}

declare_builtin_rules! {
    // ip rules
    "@ip" => rule_alias!("@ip:replace");
    "@ip:replace" => RuleSpec {
        ty: RuleType::Ip,
        redaction: Redaction::Replace {
            text: "[ip]".into(),
        },
    };
    "@ip:hash" => RuleSpec {
        ty: RuleType::Ip,
        redaction: Redaction::Hash {
            algorithm: HashAlgorithm::HmacSha1,
            key: None,
        },
    };

    // imei rules
    "@imei" => rule_alias!("@imei:replace");
    "@imei:replace" => RuleSpec {
        ty: RuleType::Imei,
        redaction: Redaction::Replace {
            text: "[imei]".into(),
        },
    };
    "@imei:hash" => RuleSpec {
        ty: RuleType::Imei,
        redaction: Redaction::Hash {
            algorithm: HashAlgorithm::HmacSha1,
            key: None,
        },
    };

    // mac rules
    "@mac" => rule_alias!("@mac:mask");
    "@mac:replace" => RuleSpec {
        ty: RuleType::Mac,
        redaction: Redaction::Replace {
            text: "[mac]".into(),
        },
    };
    "@mac:mask" => RuleSpec {
        ty: RuleType::Mac,
        redaction: Redaction::Mask {
            mask_char: '*',
            chars_to_ignore: "-:".into(),
            range: (Some(9), None),
        },
    };
    "@mac:hash" => RuleSpec {
        ty: RuleType::Mac,
        redaction: Redaction::Hash {
            algorithm: HashAlgorithm::HmacSha1,
            key: None,
        },
    };

    // email rules
    "@email" => rule_alias!("@email:replace");
    "@email:mask" => RuleSpec {
        ty: RuleType::Email,
        redaction: Redaction::Mask {
            mask_char: '*',
            chars_to_ignore: ".@".into(),
            range: (None, None),
        },
    };
    "@email:replace" => RuleSpec {
        ty: RuleType::Email,
        redaction: Redaction::Replace {
            text: "[email]".into(),
        },
    };
    "@email:hash" => RuleSpec {
        ty: RuleType::Email,
        redaction: Redaction::Hash {
            algorithm: HashAlgorithm::HmacSha1,
            key: None,
        },
    };

    // creditcard rules
    "@creditcard" => rule_alias!("@creditcard:mask");
    "@creditcard:mask" => RuleSpec {
        ty: RuleType::Creditcard,
        redaction: Redaction::Mask {
            mask_char: '*',
            chars_to_ignore: " -".into(),
            range: (None, Some(-4)),
        },
    };
    "@creditcard:replace" => RuleSpec {
        ty: RuleType::Creditcard,
        redaction: Redaction::Replace {
            text: "[creditcard]".into(),
        },
    };
    "@creditcard:hash" => RuleSpec {
        ty: RuleType::Creditcard,
        redaction: Redaction::Hash {
            algorithm: HashAlgorithm::HmacSha1,
            key: None,
        },
    };

    // user path rules
    "@userpath" => rule_alias!("@userpath:replace");
    "@userpath:replace" => RuleSpec {
        ty: RuleType::Userpath,
        redaction: Redaction::Replace {
            text: "[user]".into(),
        },
    };
    "@userpath:hash" => RuleSpec {
        ty: RuleType::Userpath,
        redaction: Redaction::Hash {
            algorithm: HashAlgorithm::HmacSha1,
            key: None,
        },
    };

    // password field removal
    "@password" => rule_alias!("@password:remove");
    "@password:remove" => RuleSpec {
        ty: RuleType::RedactPair {
            key_pattern: "(?i)\\b(password|passwd|mysql_pwd|auth|credentials|secret)\\b".into(),
        },
        redaction: Redaction::Remove,
    };
}
