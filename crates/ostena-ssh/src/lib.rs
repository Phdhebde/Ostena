//! Native SSH access (ADR-0010): the frozen algorithm list, the pre-check
//! that refuses a peer without strict KEX or without a common algorithm
//! before the SSH library reads it, and the library configuration.
//!
//! The SSH library brings its own cryptography: an exception accepted for
//! this crate only (ADR-0009, `deny.toml`).

#![forbid(unsafe_code)]

pub mod algorithms;
#[cfg(feature = "russh")]
pub mod config;
pub mod precheck;

#[doc(hidden)]
pub mod fuzz;
