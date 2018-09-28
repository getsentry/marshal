extern crate console;
extern crate dialoguer;
extern crate difference;
extern crate failure;
extern crate marshal;
extern crate serde_json;

use std::fs;
use std::path::Path;

use console::style;
use dialoguer::{Confirmation, Editor, Input};
use difference::Changeset;
use failure::Error;
use marshal::processor::PiiConfig;
use marshal::protocol::{Annotated, Event};
use serde_json::Value;

static PII_CONFIG: &str = r#"{
  "applications": {
    "freeform": []
  }
}"#;

fn main() {
    match run() {
        Ok(()) => (),
        Err(e) => println!("{} {}", style("error").red(), e),
    }
}

fn pretty(json: &str) -> Result<String, Error> {
    Ok(format!("{:#}", json.parse::<Value>()?))
}

fn check_diff(name: &str, before: &str, after: &str) -> Result<bool, Error> {
    if before == after {
        println!(
            "{} Please check {}:\n(no differences)",
            style(">").dim(),
            name
        );
    } else {
        println!(
            "{} Please check {}:\n{}\n{}",
            style(">").dim(),
            name,
            Changeset::new("- before", "+ after", "\n"),
            Changeset::new(&pretty(before)?, &pretty(after)?, "\n")
        );
    }

    Ok(Confirmation::new("Look good?").clear(false).interact()?)
}

macro_rules! car {
    ($str:expr) => {
        &format!("{} {}", style(">").dim(), $str)
    };
}

fn run() -> Result<(), Error> {
    let name = Input::new(car!("Test payload name")).interact()?;

    if Path::new(&format!("tests/payloads/{}.json", name)).exists() {
        let overwrite = Confirmation::new(car!("Test already exists. Overwrite?"))
            .clear(false)
            .interact()?;

        if !overwrite {
            println!("{}", style("Aborting.").yellow());
            return Ok(());
        }
    }

    Confirmation::new(car!("Enter payload JSON in the editor [press ENTER]"))
        .show_default(false)
        .interact()?;

    let payload = match Editor::new().extension("json").edit("")? {
        Some(input) => pretty(&input)?,
        None => {
            println!("{}", style("Aborting.").yellow());
            return Ok(());
        }
    };

    let event = Annotated::<Event>::from_json(&payload)?;
    let normalized = event.to_json_pretty()?;
    if !check_diff("normalization", &payload, &normalized)? {
        println!("{}", style("Aborting.").yellow());
        return Ok(());
    }

    let stripped = PiiConfig::from_json(PII_CONFIG)?
        .processor()
        .process_root_value(event)
        .to_json_pretty()?;

    if !check_diff("PII stripping", &normalized, &normalized)? {
        println!("{}", style("Aborting.").yellow());
        return Ok(());
    }

    println!("{}", car!("Saving files..."));
    println!();

    fs::write(format!("tests/payloads/{}.json", name), payload)?;
    println!(
        "{} {}",
        style("A").green(),
        format!("tests/payloads/{}.json", name)
    );

    fs::write(format!("tests/normalize/{}.json", name), normalized)?;
    println!(
        "{} {}",
        style("A").green(),
        format!("tests/normalize/{}.json", name)
    );

    fs::write(format!("tests/strip/{}.json", name), stripped)?;
    println!(
        "{} {}",
        style("A").green(),
        format!("tests/strip/{}.json", name)
    );

    println!();
    println!("All done. Don't forget to add the test in `tests/payloads.rs`:");
    println!("  {}", style(&format!("run!($mode, {});", name)).dim());

    Ok(())
}
