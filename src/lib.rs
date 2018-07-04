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
extern crate serde_json;
extern crate uuid;

pub mod chunk;
pub mod common;
pub mod meta;
pub mod protocol;
pub mod rule;

mod tracked;
mod unexpected;
mod utils;

#[cfg(test)]
mod tests;
