extern crate difference;
extern crate marshal;

use std::fs;
use std::path::Path;

use marshal::processor::PiiConfig;
use marshal::protocol::{Annotated, Event};

static PII_CONFIG: &str = r#"{
  "applications": {
    "freeform": []
  }
}"#;

// XXX: Copy/paste from testutils.rs
macro_rules! assert_eq_str {
    ($left:expr, $right:expr) => {{
        let left = &($left);
        let right = &$right;

        assert!(
            left == right,
            "`left == right` in line {}:\n{}\n{}",
            line!(),
            ::difference::Changeset::new("- left", "+ right", "\n"),
            ::difference::Changeset::new(&left, &right, "\n")
        )
    }};
}

fn read_fixture<P: AsRef<Path>>(path: P) -> String {
    let full_path = Path::new("tests/").join(path.as_ref());
    let mut string = fs::read_to_string(full_path)
        .unwrap_or_else(|_| panic!("failed to read fixture '{}'", path.as_ref().display()));

    if string.ends_with('\n') {
        let len = string.len();
        string.truncate(len - 1);
    }

    string
}

macro_rules! run {
    ($mode:ident, $sdk:ident) => {
        #[test]
        fn $sdk() {
            let input = read_fixture(concat!("payloads/", stringify!($sdk), ".json"));
            let expected = read_fixture(concat!(stringify!($mode), "/", stringify!($sdk), ".json"));
            let actual = super::$mode(&input);
            assert_eq_str!(expected, actual);
        }
    };
}

fn normalize(input: &str) -> String {
    let event = Annotated::<Event>::from_json(input).expect("could not parse event");
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
            use super::read_fixture;

            run!($mode, cocoa);
            run!($mode, dotnet);
            run!($mode, electron_main);
            run!($mode, electron_renderer);
            run!($mode, swift);
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
