//! Native SSH access (ADR-0010): the frozen algorithm list, the pre-check
//! that refuses a peer without strict KEX or without a common algorithm
//! before the SSH library reads it, the library configuration, the OpenSSH
//! certificates of `ostena login` and of the agent, and the session path:
//! the agent server ([`server`]) and the driver to the targets ([`driver`]).
//!
//! The SSH library brings its own cryptography: an exception accepted for
//! this crate only (ADR-0009, `deny.toml`). Certificates are signed and
//! checked a second time by `ostena-crypto` ([`cert`]).

#![forbid(unsafe_code)]

pub mod algorithms;
pub mod cert;
#[cfg(feature = "russh")]
pub mod config;
#[cfg(feature = "russh")]
pub mod driver;
mod error;
pub mod keys;
pub mod login;
pub mod precheck;
#[cfg(feature = "russh")]
pub mod server;
pub mod transcript;

pub use error::SshError;

#[doc(hidden)]
pub mod fuzz;
