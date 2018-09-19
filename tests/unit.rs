extern crate difference;
extern crate marshal;

#[macro_use]
mod common;

use std::path::Path;

use marshal::processor::PiiConfig;
use marshal::protocol::{Annotated, Event};
use common::read_fixture;

macro_rules! run {
    ($name:ident) => {
        #[test]
        fn $name() {
            let base = Path::new("unit").join(stringify!($name));
            let config = PiiConfig::from_json(&read_fixture(
                base.join("config.json")
            )).unwrap();
            let input = Annotated::<Event>::from_json(&read_fixture(
                base.join("event.json")
            )).unwrap();
            let expected_output = read_fixture(base.join("expected.json"));

            assert_eq_str!(expected_output, config.processor().process_root_value(input).to_json_pretty().unwrap());
        }
    }
}

run!(strip_headers_by_name);
run!(redact_pair_deletes_already_processed_value);
run!(redact_pair_is_not_undone_by_other_rule);
