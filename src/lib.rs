//! Event processing library used at Sentry.
//!
//! This crate contains types and utility functions for parsing Sentry event payloads, normalizing
//! them into the canonical protocol, and stripping PII.

#![warn(missing_docs)]

extern crate chrono;
extern crate cookie;
extern crate debugid;
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate lazy_static;
extern crate hmac;
extern crate queryst;
extern crate regex;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate sha1;
extern crate sha2;
extern crate uuid;

#[macro_use]
extern crate marshal_derive;

#[cfg(test)]
extern crate difference;

#[cfg(test)]
#[macro_use]
mod testutils;

pub mod processor;
pub mod protocol;
