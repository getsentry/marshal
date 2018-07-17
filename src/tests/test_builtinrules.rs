use std::collections::BTreeMap;

use common::{Map, Value};
use meta::{Annotated, Remark, RemarkType};
use processor::PiiKind;
use rule::PiiConfig;

#[derive(ProcessAnnotatedValue, Debug, Deserialize, Serialize, Clone, PartialEq)]
struct FreeformRoot {
    #[process_annotated_value(pii_kind = "freeform")]
    value: Annotated<String>,
}

macro_rules! valuemap {
        () => { Map::<Value>::new() };
        ($($key:expr => $value:expr),* $(,)*) => {{
            let mut __map = Map::<Value>::new();
            $(
                __map.insert($key.to_string(), Annotated::from($value));
            )*
            __map
        }}
    }

macro_rules! assert_freeform_rule {
    (rule = $rule:expr; input = $input:expr; output = $output:expr; remarks = $remarks:expr;) => {{
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
        let processor = config.processor();
        let root = Annotated::from(FreeformRoot {
            value: Annotated::from(input),
        });
        let processed_root = processor.process_root_value(root);
        let root = processed_root.0.unwrap();
        assert_eq_str!(root.value.value().unwrap(), $output);
        assert_eq_dbg!(&root.value.meta().remarks, &$remarks);
    }};
}

#[derive(ProcessAnnotatedValue, Debug, Deserialize, Serialize, Clone)]
struct DatabagRoot {
    #[process_annotated_value(pii_kind = "databag")]
    value: Annotated<Map<Value>>,
}

macro_rules! assert_databag_rule {
    (rule = $rule:expr; input = $input:expr; output = $output:expr; remarks = $remarks:expr;) => {{
        let config = PiiConfig {
            rules: Default::default(),
            vars: Default::default(),
            applications: {
                let mut map = BTreeMap::new();
                map.insert(PiiKind::Databag, vec![$rule.to_string()]);
                map
            },
        };
        let input = $input;
        let output = $output;
        let processor = config.processor();
        let root = Annotated::from(DatabagRoot {
            value: Annotated::from(input),
        });
        // we need to go through json so that path information is available
        let json_root = root.to_json().unwrap();
        let root = Annotated::<DatabagRoot>::from_json(&json_root).unwrap();
        let processed_root = processor.process_root_value(root);
        let root = processed_root.0.unwrap();
        assert_eq_dbg!(root.value.value().unwrap(), &output);
        assert_eq_dbg!(&root.value.meta().remarks, &$remarks);
    }};
}

#[test]
fn test_ipv4() {
    assert_freeform_rule!(
            rule = "@ip";
            input = "before 127.0.0.1 after";
            output = "before [ip] after";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@ip:replace", (7, 11)),
            ];
        );
    assert_freeform_rule!(
            rule = "@ip:replace";
            input = "before 127.0.0.1 after";
            output = "before [ip] after";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@ip:replace", (7, 11)),
            ];
        );
    assert_freeform_rule!(
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
    assert_freeform_rule!(
            rule = "@ip";
            input = "before ::1 after";
            output = "before [ip] after";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@ip:replace", (7, 11)),
            ];
        );
    assert_freeform_rule!(
            rule = "@ip";
            input = "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]";
            output = "[[ip]]";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@ip:replace", (1, 5)),
            ];
        );
    assert_freeform_rule!(
            rule = "@ip:hash";
            input = "before 2001:0db8:85a3:0000:0000:8a2e:0370:7334 after";
            output = "before 8C3DC9BEED9ADE493670547E24E4E45EDE69FF03 after";
            remarks = vec![
                Remark::with_range(RemarkType::Pseudonymized, "@ip:hash", (7, 47)),
            ];
        );
    assert_freeform_rule!(
            rule = "@ip";
            input = "foo::1";
            output = "foo::1";
            remarks = vec![];
        );
}

#[test]
fn test_imei() {
    assert_freeform_rule!(
            rule = "@imei";
            input = "before 356938035643809 after";
            output = "before [imei] after";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@imei:replace", (7, 13)),
            ];
        );
    assert_freeform_rule!(
            rule = "@imei:replace";
            input = "before 356938035643809 after";
            output = "before [imei] after";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@imei:replace", (7, 13)),
            ];
        );
    assert_freeform_rule!(
            rule = "@imei:hash";
            input = "before 356938035643809 after";
            output = "before 3888108AA99417402969D0B47A2CA4ECD2A1AAD3 after";
            remarks = vec![
                Remark::with_range(RemarkType::Pseudonymized, "@imei:hash", (7, 47)),
            ];
        );
}

#[test]
fn test_mac() {
    assert_freeform_rule!(
            rule = "@mac";
            input = "ether 4a:00:04:10:9b:50";
            output = "ether 4a:00:04:**:**:**";
            remarks = vec![
                Remark::with_range(RemarkType::Masked, "@mac:mask", (6, 23)),
            ];
        );
    assert_freeform_rule!(
            rule = "@mac:mask";
            input = "ether 4a:00:04:10:9b:50";
            output = "ether 4a:00:04:**:**:**";
            remarks = vec![
                Remark::with_range(RemarkType::Masked, "@mac:mask", (6, 23)),
            ];
        );
    assert_freeform_rule!(
            rule = "@mac:replace";
            input = "ether 4a:00:04:10:9b:50";
            output = "ether [mac]";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@mac:replace", (6, 11)),
            ];
        );
    assert_freeform_rule!(
            rule = "@mac:hash";
            input = "ether 4a:00:04:10:9b:50";
            output = "ether 6220F3EE59BF56B32C98323D7DE43286AAF1F8F1";
            remarks = vec![
                Remark::with_range(RemarkType::Pseudonymized, "@mac:hash", (6, 46)),
            ];
        );
}

#[test]
fn test_email() {
    assert_freeform_rule!(
            rule = "@email";
            input = "John Appleseed <john@appleseed.com>";
            output = "John Appleseed <[email]>";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@email:replace", (16, 23)),
            ];
        );
    assert_freeform_rule!(
            rule = "@email:replace";
            input = "John Appleseed <john@appleseed.com>";
            output = "John Appleseed <[email]>";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@email:replace", (16, 23)),
            ];
        );
    assert_freeform_rule!(
            rule = "@email:mask";
            input = "John Appleseed <john@appleseed.com>";
            output = "John Appleseed <****@*********.***>";
            remarks = vec![
                Remark::with_range(RemarkType::Masked, "@email:mask", (16, 34)),
            ];
        );
    assert_freeform_rule!(
            rule = "@email:hash";
            input = "John Appleseed <john@appleseed.com>";
            output = "John Appleseed <33835528AC0FFF1B46D167C35FEAAA6F08FD3F46>";
            remarks = vec![
                Remark::with_range(RemarkType::Pseudonymized, "@email:hash", (16, 56)),
            ];
        );
}

#[test]
fn test_creditcard() {
    assert_freeform_rule!(
            rule = "@creditcard";
            input = "John Appleseed 1234-1234-1234-1234!";
            output = "John Appleseed ****-****-****-1234!";
            remarks = vec![
                Remark::with_range(RemarkType::Masked, "@creditcard:mask", (15, 34)),
            ];
        );
    assert_freeform_rule!(
            rule = "@creditcard:mask";
            input = "John Appleseed 1234-1234-1234-1234!";
            output = "John Appleseed ****-****-****-1234!";
            remarks = vec![
                Remark::with_range(RemarkType::Masked, "@creditcard:mask", (15, 34)),
            ];
        );
    assert_freeform_rule!(
            rule = "@creditcard:replace";
            input = "John Appleseed 1234-1234-1234-1234!";
            output = "John Appleseed [creditcard]!";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@creditcard:replace", (15, 27)),
            ];
        );
    assert_freeform_rule!(
            rule = "@creditcard:hash";
            input = "John Appleseed 1234-1234-1234-1234!";
            output = "John Appleseed 97227DBC2C4F028628CE96E0A3777F97C07BBC84!";
            remarks = vec![
                Remark::with_range(RemarkType::Pseudonymized, "@creditcard:hash", (15, 55)),
            ];
        );
}

#[test]
fn test_userpath() {
    assert_freeform_rule!(
            rule = "@userpath";
            input = "C:\\Users\\mitsuhiko\\Desktop";
            output = "C:\\Users\\[user]\\Desktop";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@userpath:replace", (9, 15)),
            ];
        );
    assert_freeform_rule!(
            rule = "@userpath";
            input = "File in /Users/mitsuhiko/Development/sentry-stripping";
            output = "File in /Users/[user]/Development/sentry-stripping";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@userpath:replace", (15, 21)),
            ];
        );
    assert_freeform_rule!(
            rule = "@userpath:replace";
            input = "C:\\Windows\\Profiles\\Armin\\Temp";
            output = "C:\\Windows\\Profiles\\[user]\\Temp";
            remarks = vec![
                Remark::with_range(RemarkType::Substituted, "@userpath:replace", (20, 26)),
            ];
        );
    assert_freeform_rule!(
            rule = "@userpath:hash";
            input = "File in /Users/mitsuhiko/Development/sentry-stripping";
            output = "File in /Users/A8791A1A8D11583E0200CC1B9AB971B4D78B8A69/Development/sentry-stripping";
            remarks = vec![
                Remark::with_range(RemarkType::Pseudonymized, "@userpath:hash", (15, 55)),
            ];
        );
}

#[test]
fn test_password() {
    assert_databag_rule!(
            rule = "@password";
            input = valuemap!{
                "password" => Value::from("testing"),
                "some_other_key" => Value::from(true),
            };
            output = valuemap!{
                "password" => Annotated::from(Value::from("".to_string()))
                        .with_removed_value(Remark::new(RemarkType::Removed, "@password:remove")),
                "some_other_key" =>
                    Annotated::from(Value::from(true)),
            };
            remarks = vec![];
        );
}
