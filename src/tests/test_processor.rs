use common::Value;
use meta::Annotated;
use processor::*;

#[test]
fn test_basic_processing() {
    #[derive(ProcessAnnotatedValue)]
    struct Event {
        flag: bool,
        #[process_annotated_value]
        id: Annotated<u32>,
        #[process_annotated_value(pii_kind = "freeform", cap = "message")]
        message: Annotated<String>,
    }

    struct MyProcessor;

    impl Processor for MyProcessor {
        fn process_u32(&self, mut annotated: Annotated<u32>, _info: &ValueInfo) -> Annotated<u32> {
            annotated.set_value(None);
            annotated.meta_mut().errors.push("Whatever mate".into());
            annotated
        }
    }

    let event = Annotated::from(Event {
        flag: true,
        id: Annotated::from(42),
        message: Annotated::from("Hello World!".to_string()),
    });

    let new_event =
        ProcessAnnotatedValue::process_annotated_value(event, &MyProcessor, &ValueInfo::default());
    let id = new_event.0.unwrap().id;
    assert_eq_dbg!(id, Annotated::from_error("Whatever mate"));
}

#[test]
fn test_pii_processing() {
    use meta::RemarkType;

    #[derive(ProcessAnnotatedValue)]
    struct Event {
        flag: bool,
        #[process_annotated_value(pii_kind = "id")]
        id: Annotated<u32>,
        #[process_annotated_value(pii_kind = "freeform")]
        message: Annotated<String>,
    }

    struct MyPiiProcessor;

    impl PiiProcessor for MyPiiProcessor {
        fn pii_process_value(
            &self,
            annotated: Annotated<Value>,
            pii_kind: PiiKind,
        ) -> Annotated<Value> {
            use meta::Remark;
            match (annotated, pii_kind) {
                (annotated, PiiKind::Id) => {
                    annotated.with_removed_value(Remark::new(RemarkType::Removed, "@id-removed"))
                }
                (annotated, _) => annotated,
            }
        }
    }

    let event = Annotated::from(Event {
        flag: true,
        id: Annotated::from(42),
        message: Annotated::from("Hello World!".to_string()),
    });

    let new_event = ProcessAnnotatedValue::process_annotated_value(
        event,
        &MyPiiProcessor,
        &ValueInfo::default(),
    );
    let id = new_event.0.unwrap().id;
    assert!(id.value().is_none());
    assert_eq_str!(id.meta().remarks().next().unwrap().rule_id(), "@id-removed");
}
