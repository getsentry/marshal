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
}

#[cfg(test)]
mod test {
    use meta::{Annotated, Remark, RemarkType};
    use processor::PiiKind;
    use rule::PiiConfig;
    use std::collections::BTreeMap;

    #[derive(ProcessAnnotatedValue, Debug, Deserialize, Serialize, Clone)]
    struct Root {
        #[process_annotated_value(pii_kind = "freeform")]
        value: Annotated<String>,
    }

    macro_rules! assert_rule {
        (
            rule = $rule:expr; input = $input:expr; output = $output:expr; remarks = $remarks:expr;
        ) => {{
            let config = PiiConfig {
                rules: Default::default(),
                vars: Default::default(),
                applications: {
                    let mut map = BTreeMap::new();
                    map.insert(PiiKind::Freeform, vec![$rule.to_string()]);
                    map
                },
            };
            let input = $input.to_string();
            println!();
            println!("  input: {}", &input);
            println!("  expected output: {}", $output);
            let processor = config.processor();
            let root = Annotated::from(Root {
                value: Annotated::from(input),
            });
            let processed_root = processor.process_root_value(root);
            println!(
                "  output: {}",
                processed_root.value().unwrap().value.value().unwrap()
            );
            println!("{:#?}", processed_root);
            let root = processed_root.0.unwrap();
            assert_eq!(root.value.value().unwrap(), $output);
            assert_eq!(&root.value.meta().remarks, &$remarks);
        }};
    }

    #[test]
    fn test_ipv4() {
        assert_rule!(
            rule = "@ip";
            input = "before 127.0.0.1 after";
            output = "before [ip] after";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@ip:replace", (7, 11)),
            ];
        );
        assert_rule!(
            rule = "@ip:replace";
            input = "before 127.0.0.1 after";
            output = "before [ip] after";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@ip:replace", (7, 11)),
            ];
        );
        assert_rule!(
            rule = "@ip:hash";
            input = "before 127.0.0.1 after";
            output = "before AE12FE3B5F129B5CC4CDD2B136B7B7947C4D2741 after";
            remarks = vec![
                Remark::with_range(RemarkType::Pseudonymized, "@ip:hash", (7, 47)),
            ];
        );
    }

    #[test]
    fn test_ipv6() {
        assert_rule!(
            rule = "@ip";
            input = "before ::1 after";
            output = "before [ip] after";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@ip:replace", (7, 11)),
            ];
        );
        assert_rule!(
            rule = "@ip";
            input = "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]";
            output = "[[ip]]";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@ip:replace", (1, 5)),
            ];
        );
        assert_rule!(
            rule = "@ip:hash";
            input = "before 2001:0db8:85a3:0000:0000:8a2e:0370:7334 after";
            output = "before 8C3DC9BEED9ADE493670547E24E4E45EDE69FF03 after";
            remarks = vec![
                Remark::with_range(RemarkType::Pseudonymized, "@ip:hash", (7, 47)),
            ];
        );
        assert_rule!(
            rule = "@ip";
            input = "foo::1";
            output = "foo::1";
            remarks = vec![];
        );
    }

    #[test]
    fn test_imei() {
        assert_rule!(
            rule = "@imei";
            input = "before 356938035643809 after";
            output = "before [imei] after";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@imei:replace", (7, 13)),
            ];
        );
        assert_rule!(
            rule = "@imei:replace";
            input = "before 356938035643809 after";
            output = "before [imei] after";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@imei:replace", (7, 13)),
            ];
        );
        assert_rule!(
            rule = "@imei:hash";
            input = "before 356938035643809 after";
            output = "before 3888108AA99417402969D0B47A2CA4ECD2A1AAD3 after";
            remarks = vec![
                Remark::with_range(RemarkType::Pseudonymized, "@imei:hash", (7, 47)),
            ];
        );
    }
}
