//! The core (ADR-0011): agent registry and enrolment tokens in PostgreSQL,
//! tunnel and enrolment listeners.

#![forbid(unsafe_code)]

pub mod cache;
pub mod db;
mod error;
pub mod schema;
pub mod server;
pub mod store;

pub use error::CoreError;
