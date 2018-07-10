//! Event processing library used at Sentry.
//!
//! This crate contains types and utility functions for parsing Sentry event payloads, normalizing
//! them into the canonical protocol, and stripping PII.

#![warn(missing_docs)]

extern crate chrono;
extern crate regex;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate failure;
extern crate serde_json;
extern crate uuid;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate sentry_stripping_derive;

pub use {
    chunk::*,
    common::*,
    meta::*,
    protocol::*,
    processor::*,
    rule::*,
    value::*
};

mod chunk;
mod common;
mod meta;
mod protocol;
mod rule;
mod value;
mod meta_ser;
mod tracked;
mod utils;
mod processor;
