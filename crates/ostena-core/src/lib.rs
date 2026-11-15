//! The core (ADR-0011): agent registry and enrolment tokens in PostgreSQL,
//! tunnel and enrolment listeners, audit chain (ADR-0012).

#![forbid(unsafe_code)]

pub mod audit;
pub mod cache;
pub mod db;
mod error;
pub mod schema;
pub mod server;
pub mod store;
#[cfg(feature = "testing")]
pub mod testing;

pub use error::CoreError;
