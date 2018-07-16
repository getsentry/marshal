use chunk::*;
use meta::{Meta, Remark, RemarkType};

#[test]
fn test_chunking() {
    let chunks = chunks_from_str(
        "Hello Peter, my email address is ****@*****.com. See you",
        &Meta {
            remarks: vec![Remark::with_range(
                RemarkType::Masked,
                "@email:strip",
                (33, 47),
            )],
            ..Default::default()
        },
    );

    assert_eq_dbg!(
        chunks,
        vec![
            Chunk::Text {
                text: "Hello Peter, my email address is ".into(),
            },
            Chunk::Redaction {
                ty: RemarkType::Masked,
                text: "****@*****.com".into(),
                rule_id: "@email:strip".into(),
            },
            Chunk::Text {
                text: ". See you".into(),
            },
        ]
    );

    assert_eq_dbg!(
        chunks_to_string(chunks, Default::default()),
        (
            "Hello Peter, my email address is ****@*****.com. See you".into(),
            Meta {
                remarks: vec![Remark::with_range(
                    RemarkType::Masked,
                    "@email:strip",
                    (33, 47),
                )],
                ..Default::default()
            }
        )
    );
}
