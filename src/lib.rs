//! Event processing library used at Sentry.
//!
//! This crate contains types and utility functions for parsing Sentry event payloads, normalizing
//! them into the canonical protocol, and stripping PII.

#![warn(missing_docs)]

extern crate chrono;
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate lazy_static;
extern crate regex;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate uuid;

#[allow(unused_imports)]
#[macro_use]
extern crate sentry_stripping_derive;

pub use {chunk::*, meta::*, processor::*, rule::*};

#[macro_use]
mod macros;

mod chunk;
mod common;
mod meta;
mod meta_ser;
mod processor;
mod rule;
mod tracked;
mod utils;

pub mod protocol;
