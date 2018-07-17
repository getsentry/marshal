use common::{Map, Value};
use meta::{Annotated, Meta, Remark, RemarkType};
use rule::PiiConfig;

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

    let foo = new_event.extra.value().unwrap().get("foo").unwrap();
    assert!(foo.value().is_none());
    assert_eq_dbg!(
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
    assert_eq_dbg!(
        ip.meta(),
        &Meta {
            remarks: vec![Remark::new(RemarkType::Removed, "remove_ip")],
            errors: vec![],
            original_length: None,
            path: None,
        }
    );

    let value = processed_event.to_json().unwrap();
    assert_eq_str!(value, "{\"message\":\"Hello *****@*****.***.  You signed up with card ****-****-****-1234. Your home folder is C:\\\\Users\\\\[username] Look at our compliance from 5A2DF387CD660E9F3E0AB20F9E7805450D56C5DACE9B959FC620C336E2B5D09A\",\"extra\":{\"bar\":true,\"foo\":null},\"ip\":null,\"\":{\"extra\":{\"foo\":{\"\":{\"rem\":[[\"remove_foo\",\"x\"]]}}},\"ip\":{\"\":{\"rem\":[[\"remove_ip\",\"x\"]]}},\"message\":{\"\":{\"len\":142,\"rem\":[[\"email_address\",\"m\",6,21],[\"creditcard_number\",\"m\",48,67],[\"path_username\",\"s\",98,108],[\"hash_ip\",\"p\",137,201]]}}}}");
}

#[test]
fn test_well_known_stripping() {
    use meta::Remark;

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

    let value = processed_event.to_json().unwrap();
    assert_eq_str!(value, "{\"message\":\"[user-id] on [device-id] ([ip]): Hello World!\",\"\":{\"message\":{\"\":{\"len\":62,\"rem\":[[\"user_id\",\"s\",0,9],[\"device_id\",\"s\",13,24],[\"@ip:replace\",\"s\",26,30]]}}}}");
}

#[test]
fn test_well_known_stripping_common_redaction() {
    use meta::Remark;

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

    let value = processed_event.to_json().unwrap();
    assert_eq_str!(value, "{\"message\":\"[id] on [id] ([id]): Hello World!\",\"\":{\"message\":{\"\":{\"len\":62,\"rem\":[[\"ids\",\"s\",0,4],[\"ids\",\"s\",8,12],[\"ids\",\"s\",14,18]]}}}}");
}
