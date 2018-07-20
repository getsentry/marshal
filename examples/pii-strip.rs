extern crate failure;
extern crate marshal;

use std::env;
use std::fs;

use failure::Error;

use marshal::processor::PiiConfig;
use marshal::protocol::{Annotated, Event};

fn main() {
    run().unwrap();
}

fn run() -> Result<(), Error> {
    let args: Vec<_> = env::args().collect();
    let json_config = fs::read_to_string(&args[1])?;
    let config = PiiConfig::from_json(&json_config)?;
    let processor = config.processor();
    let json_event = fs::read_to_string(&args[2])?;
    let event = Annotated::<Event>::from_json(&json_event)?;
    println!("RULES:");
    println!("{}", config.to_json_pretty()?);
    println!("");
    println!("INPUT:");
    println!("{}", event.to_json_pretty()?);
    let result = processor.process_root_value(event);
    println!("");
    println!("OUTPUT:");
    println!("{}", result.to_json_pretty()?);
    Ok(())
}
