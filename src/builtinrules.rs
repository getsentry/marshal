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

declare_builtin_rules! {
    "@ip" => RuleSpec {
        ty: RuleType::Alias {
            rule: "@ip:replace".into(),
            hide_rule: true,
        },
        redaction: Redaction::Default,
    };

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

    "@email" => RuleSpec {
        ty: RuleType::Alias {
            rule: "@email:replace".into(),
            hide_rule: true,
        },
        redaction: Redaction::Default,
    };

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

    "@creditcard" => RuleSpec {
        ty: RuleType::Alias {
            rule: "@creditcard:mask".into(),
            hide_rule: true,
        },
        redaction: Redaction::Default,
    };

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
}
