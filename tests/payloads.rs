extern crate difference;
extern crate marshal;

#[macro_use]
mod common;

use marshal::processor::PiiConfig;
use marshal::protocol::{Annotated, Event};

static PII_CONFIG: &str = r#"{
  "applications": {
    "freeform": []
  }
}"#;

macro_rules! run {
    ($mode:ident, $sdk:ident) => {
        #[test]
        fn $sdk() {
            let input = read_fixture(concat!("payloads/payloads/", stringify!($sdk), ".json"));
            let expected = read_fixture(concat!(
                "payloads/",
                stringify!($mode),
                "/",
                stringify!($sdk),
                ".json"
            ));
            let actual = super::$mode(&input);
            assert_eq_str!(expected, actual);
        }
    };
}

fn normalize(input: &str) -> String {
    let event = Annotated::<Event>::from_json(input).expect("could not parse event");
    println!("other: {:?}", event.value().unwrap().other.value().unwrap());
    event.to_json_pretty().expect("could not stringify event")
}

fn strip(input: &str) -> String {
    let event = Annotated::<Event>::from_json(input).expect("could not parse event");
    let result = PiiConfig::from_json(PII_CONFIG)
        .expect("could not parse PII config")
        .processor()
        .process_root_value(event);
    result.to_json_pretty().expect("could not stringify event")
}

macro_rules! test_all {
    ($mode:ident) => {
        mod $mode {
            use super::common::read_fixture;

            run!($mode, legacy_js_exception);
            run!($mode, legacy_js_message);
            run!($mode, legacy_js_onerror);
            run!($mode, legacy_js_promise);
            run!($mode, legacy_node_exception);
            run!($mode, legacy_node_express);
            run!($mode, legacy_node_message);
            run!($mode, legacy_node_onerror);
            run!($mode, legacy_node_promise);
            run!($mode, legacy_python);
            run!($mode, legacy_swift);

            run!($mode, cocoa);
            run!($mode, cordova);
            run!($mode, dotnet);
            run!($mode, electron_main);
            run!($mode, electron_renderer);

            // To add new tests, run:
            // cargo run --example add-test
        }
    };
}

test_all!(normalize);
test_all!(strip);

// NOTE: @ip has false-positives in dotnet
//       "System.Private.CoreLib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e"
//       "System.Private.CoreLib, Version=[ip], Culture=neutral, PublicKeyToken=7cec85d7bea7798e"

// NOTE: @userpath has false-positives in dotnet
//       "Request starting HTTP/1.1 POST http://localhost:62919/Home/PostIndex application/json; charset=UTF-8 65"
//       "Request starting HTTP/1.1 POST http://localhost:62919/Home/[user]/json; charset=UTF-8 65"

// NOTE: @email has false-positives in electron_main
//       "sentry-electron-test@2.0.2"
//       "[email]"
